//! Native, offline operations on an Ubuntu root directory.
//!
//! The directory is a bounded staging view produced by `ext4_mountless`; it
//! is never treated as a general host path.  Filesystem changes are explicit
//! operations and guest processes can only be selected from `Command`. The
//! executor follows the existing `unsafe_chroot` namespace contract: private
//! mounts, a private PID/network namespace, an exact environment, bounded
//! output, and teardown before the caller can publish the root.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const linux = std.os.linux;

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn host() Architecture {
        return switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => .x86_64,
        };
    }
};

pub const NetworkPolicy = enum { disabled };
pub const DevicePolicy = enum { minimal };
pub const PidfdMode = enum { auto, force_unavailable, force_blocked, force_fd_exhaustion, force_unexpected };
pub const PidfdOpenFn = *const fn (pid: i32) usize;
const cleanup_timeout_ms: u64 = 90 * 1000;

pub const Limits = struct {
    max_file_bytes: u64 = 256 * 1024 * 1024,
    max_entries: usize = 16 * 1024,
};

pub const FileSource = union(enum) {
    inline_bytes: []const u8,
    host_path: []const u8,
};

pub const WriteFile = struct {
    path: []const u8,
    source: FileSource,
    mode: u32 = 0o644,
};

pub const CreateDirectory = struct {
    path: []const u8,
    mode: u32 = 0o755,
};

pub const ReplaceSymlink = struct {
    path: []const u8,
    target: []const u8,
};

pub const Cleanup = struct {
    directory: []const u8,
    /// A single `*` is supported and matches any basename.  The pattern is
    /// intentionally not a shell glob and never leaves `directory`.
    pattern: []const u8,
};

pub const Operation = union(enum) {
    write_file: WriteFile,
    create_directory: CreateDirectory,
    replace_symlink: ReplaceSymlink,
    remove: []const u8,
    cleanup: Cleanup,
};

pub const FoundEntry = struct {
    path: []u8,
    directory: bool,
};

pub const Inspection = struct {
    path: []u8,
    kind: Kind,
    size: u64,
};

pub const Kind = enum { file, directory, symlink, other };

const ParentDirectory = struct {
    dir: Io.Dir,
    name: []const u8,
};

pub const Command = union(enum) {
    update_initramfs: []const u8,
    dpkg_query,
    cloud_init_clean: struct { logs: bool = true },
};

pub const CommandOutcome = enum { succeeded, failed, timed_out };

pub const CommandRecord = struct {
    tool: []const u8,
    arguments: []const []const u8,
    outcome: CommandOutcome,
    exit_code: ?u8,
};

pub const CommandResult = struct {
    outcome: CommandOutcome,
    exit_code: ?u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *CommandResult, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

pub const ExecutorOptions = struct {
    root: *const Root,
    architecture: Architecture,
    timeout_ms: u64 = 30 * 60 * 1000,
    network: NetworkPolicy = .disabled,
    devices: DevicePolicy = .minimal,
    /// The executor requires a privileged mount namespace.  Callers may
    /// disable this only for a test runner supplied through `run_fn`.
    require_privileged_namespace: bool = true,
    pre_chroot_delay_ms: u64 = 0,
    supervisor_timeout_ms_override: ?u64 = null,
    pidfd_mode: PidfdMode = .auto,
    pidfd_open_fn: ?PidfdOpenFn = null,
    /// Test-only override for the path the init child reads to locate the
    /// staging root, replacing `/proc/self/fd/N`.  It lets a test point the
    /// bind at a different inode and prove the post-bind identity check fails
    /// closed; production code leaves it null.
    root_bind_path_override: ?[*:0]const u8 = null,
    run_fn: ?*const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        timeout_ms: u64,
    ) anyerror!CommandResult = null,
    run_context: ?*anyopaque = null,
};

pub const Executor = struct {
    allocator: Allocator,
    io: Io,
    options: ExecutorOptions,
    root_dir: Io.Dir,
    root_inode: Io.File.INode,
    root_dir_owned: bool = true,
    records: std.array_list.Managed(CommandRecord),

    pub fn init(allocator: Allocator, io: Io, options: ExecutorOptions) !Executor {
        if (options.architecture != Architecture.host()) return error.ArchitectureMismatch;
        if (options.network != .disabled) return error.NetworkPolicyViolation;
        if (options.devices != .minimal) return error.DevicePolicyViolation;
        if (options.require_privileged_namespace and
            (builtin.os.tag != .linux or std.os.linux.geteuid() != 0))
        {
            return error.PrivilegedNamespaceRequired;
        }
        const root_dir = try options.root.duplicateDir();
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .root_dir = root_dir,
            .root_inode = options.root.root_inode,
            .records = .init(allocator),
        };
    }

    pub fn deinit(self: *Executor) void {
        for (self.records.items) |record| {
            self.allocator.free(record.tool);
            for (record.arguments) |argument| self.allocator.free(argument);
            self.allocator.free(record.arguments);
        }
        self.records.deinit();
        if (self.root_dir_owned) self.root_dir.close(self.io);
        self.* = undefined;
    }

    pub fn commandRecords(self: *const Executor) []const CommandRecord {
        return self.records.items;
    }

    pub fn execute(self: *Executor, command: Command) !CommandResult {
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try self.appendCommand(&argv, command);
        const timeout_ms = @min(self.options.timeout_ms, commandTimeoutMs(command));
        const result = if (self.options.run_fn) |run_fn|
            try run_fn(
                self.options.run_context,
                self.allocator,
                self.io,
                argv.items,
                timeout_ms,
            )
        else
            try self.runIsolated(argv.items, timeout_ms);
        errdefer {
            var discard = result;
            discard.deinit(self.allocator);
        }

        const normalized_result = result;
        const outcome = normalized_result.outcome;
        const exit_code = normalized_result.exit_code;
        const tool = try self.allocator.dupe(u8, argv.items[argv.items.len - commandArgCount(command)]);
        const arguments = self.allocator.alloc([]const u8, argv.items.len) catch |err| {
            self.allocator.free(tool);
            return err;
        };
        var arguments_owned = true;
        defer if (arguments_owned) {
            self.allocator.free(tool);
            for (arguments) |argument| if (argument.len != 0) self.allocator.free(argument);
            self.allocator.free(arguments);
        };
        for (arguments) |*argument| argument.* = &.{};
        for (argv.items, 0..) |argument, index| {
            arguments[index] = try self.allocator.dupe(u8, argument);
        }
        try self.records.append(.{
            .tool = tool,
            .arguments = arguments,
            .outcome = outcome,
            .exit_code = exit_code,
        });
        std.debug.print(
            "offline-root: {s} outcome={s} exit={any}\n",
            .{ tool, @tagName(outcome), exit_code },
        );

        arguments_owned = false;

        if (outcome == .timed_out) {
            return error.CommandTimeout;
        }
        if (outcome == .failed) {
            return error.CommandFailed;
        }
        return normalized_result;
    }

    fn appendCommand(self: *Executor, argv: *std.array_list.Managed([]const u8), command: Command) !void {
        _ = self;
        switch (command) {
            .update_initramfs => |release| {
                try validateToken(release, error.InvalidKernelRelease);
                try argv.append("/usr/sbin/update-initramfs");
                try argv.append("-c");
                try argv.append("-k");
                try argv.append(release);
            },
            .dpkg_query => {
                try argv.append("/usr/bin/dpkg-query");
                try argv.append("-W");
                try argv.append("-f=${binary:Package}\t${Version}\t${Architecture}\n");
            },
            .cloud_init_clean => |options| {
                try argv.append("/usr/bin/cloud-init");
                try argv.append("clean");
                if (options.logs) try argv.append("--logs");
            },
        }
    }

    fn runIsolated(
        self: *Executor,
        guest_argv: []const []const u8,
        timeout_ms: u64,
    ) !CommandResult {
        if (builtin.os.tag != .linux) return error.UnsupportedHost;
        const host_timeout_ms = self.options.supervisor_timeout_ms_override orelse
            (std.math.add(u64, timeout_ms, cleanup_timeout_ms) catch return error.TimeoutOutOfRange);
        // Resolve the supervisor deadline before allocating any descriptor so a
        // rejected timeout leaves no file descriptor behind.
        const supervisor_deadline = try makeSupervisorDeadline(self.io, host_timeout_ms);

        // The bounded executor no longer shells out to util-linux.  A single
        // clone(2) creates PID 1 of a fresh mount/network/PID namespace, and
        // that init child performs every mount, device node, chroot,
        // capability drop and exec step with raw syscalls.  All of the data it
        // reads is prepared here and observed through copy-on-write memory; the
        // child itself only issues async-signal-safe syscalls.
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const guest_argv_z = try dupeArgvZ(arena, guest_argv);
        const guest_envp_z = try buildGuestEnvironment(arena);

        // The staging root is reached through the inherited descriptor only.
        // Its `/proc/self/fd/N` alias lets the init child re-resolve the exact
        // inode inside the new mount namespace, and the private bind mount onto
        // a dedicated mountpoint gives chroot a real mount root so the
        // pseudo-filesystems below it can be mounted.  The init child re-checks
        // the bound inode against this descriptor before chroot, so a rename
        // that races its readlink and mount fails closed instead of silently
        // redirecting the chroot.
        const root_fd_path: [*:0]const u8 = if (self.options.root_bind_path_override) |override|
            override
        else
            (try std.fmt.allocPrintSentinel(
                arena,
                "/proc/self/fd/{d}",
                .{self.root_dir.handle},
                0,
            )).ptr;
        const mountpoint = try std.fmt.allocPrintSentinel(
            arena,
            "/run/vmiz-offline-root-{d}-{d}",
            .{ linux.getpid(), self.root_dir.handle },
            0,
        );
        // Create the mountpoint on the host before entering the namespace; the
        // bind mount performed inside stays private, so only this empty
        // directory is ever visible on the host and it is removed on return.
        switch (linux.errno(linux.mkdir(mountpoint.ptr, 0o700))) {
            .SUCCESS, .EXIST => {},
            else => return error.MountpointSetupFailed,
        }
        defer _ = linux.rmdir(mountpoint.ptr);

        var request = NamespaceRequest{
            .root_fd = self.root_dir.handle,
            .root_fd_path = root_fd_path,
            .mountpoint = mountpoint.ptr,
            .argv = guest_argv_z,
            .envp = guest_envp_z,
            .guest_timeout_ms = timeout_ms,
            .kill_grace_ms = guest_kill_grace_ms,
            .pre_chroot_delay_ms = self.options.pre_chroot_delay_ms,
            .stdin_fd = -1,
            .stdout_fd = -1,
            .stderr_fd = -1,
        };

        const stack = try self.allocator.alignedAlloc(u8, .@"16", child_stack_size);
        defer self.allocator.free(stack);

        const dev_null_fd = blk: {
            const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            if (linux.errno(rc) != .SUCCESS) return error.DevNullUnavailable;
            break :blk @as(i32, @intCast(rc));
        };
        var dev_null_open = true;
        defer if (dev_null_open) {
            _ = linux.close(dev_null_fd);
        };

        const stdout_pipe = try openChildPipe();
        var stdout_pipe_open = true;
        defer if (stdout_pipe_open) closePipePair(stdout_pipe);
        const stderr_pipe = try openChildPipe();
        var stderr_pipe_open = true;
        defer if (stderr_pipe_open) closePipePair(stderr_pipe);

        request.stdin_fd = dev_null_fd;
        request.stdout_fd = stdout_pipe[1];
        request.stderr_fd = stderr_pipe[1];

        const stack_top = @intFromPtr(stack.ptr) + stack.len;
        const clone_flags: u32 = @as(u32, linux.CLONE.NEWNS) |
            @as(u32, linux.CLONE.NEWNET) |
            @as(u32, linux.CLONE.NEWPID) |
            @as(u32, @intFromEnum(linux.SIG.CHLD));
        const clone_rc = linux.clone(
            namespaceChild,
            stack_top,
            clone_flags,
            @intFromPtr(&request),
            null,
            0,
            null,
        );
        if (linux.errno(clone_rc) != .SUCCESS) return error.NamespaceSpawnFailed;
        const child_pid: i32 = @intCast(clone_rc);

        // Keep only the read ends of the pipes; the child owns stdin and the
        // write ends now.
        _ = linux.close(dev_null_fd);
        dev_null_open = false;
        _ = linux.close(stdout_pipe[1]);
        _ = linux.close(stderr_pipe[1]);
        stdout_pipe_open = false;
        stderr_pipe_open = false;

        var child = SupervisedChild{
            .pid = child_pid,
            .stdout = .{ .handle = stdout_pipe[0], .flags = .{ .nonblocking = false } },
            .stderr = .{ .handle = stderr_pipe[0], .flags = .{ .nonblocking = false } },
        };
        return self.runSupervised(&child, supervisor_deadline);
    }

    fn runSupervised(
        self: *Executor,
        child: *SupervisedChild,
        deadline: Io.Timeout,
    ) !CommandResult {
        defer child.closeStreams(self.io);
        var child_active = true;
        defer if (child_active) {
            signalChildTree(child.pid);
            reapChild(child.pid);
        };
        var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: Io.File.MultiReader = undefined;
        multi_reader.init(
            self.allocator,
            self.io,
            multi_reader_buffer.toStreams(),
            &.{ child.stdout, child.stderr },
        );
        defer multi_reader.deinit();
        const stdout_reader = multi_reader.reader(0);
        const stderr_reader = multi_reader.reader(1);
        while (multi_reader.fill(64, deadline)) |_| {
            if (stdout_reader.buffered().len > 4 * 1024 * 1024 or
                stderr_reader.buffered().len > 4 * 1024 * 1024)
            {
                return error.StreamTooLong;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            error.Timeout => return .{
                .outcome = .timed_out,
                .exit_code = null,
                .stdout = &.{},
                .stderr = &.{},
            },
            else => |read_err| return read_err,
        }
        try multi_reader.checkAnyError();
        const term = waitUntilDeadline(
            self.io,
            child.pid,
            deadline,
            self.options.pidfd_mode,
            self.options.pidfd_open_fn,
        ) catch |err| {
            if (err == error.Timeout) return .{
                .outcome = .timed_out,
                .exit_code = null,
                .stdout = &.{},
                .stderr = &.{},
            };
            return err;
        };
        child_active = false;
        const stdout = try multi_reader.toOwnedSlice(0);
        errdefer self.allocator.free(stdout);
        const stderr = try multi_reader.toOwnedSlice(1);
        const exit_code: ?u8 = switch (term) {
            .exited => |code| std.math.cast(u8, code),
            else => null,
        };
        return .{
            .outcome = if (exit_code == 0)
                .succeeded
            else if (exit_code == 124 or exit_code == 137)
                .timed_out
            else
                .failed,
            .exit_code = exit_code,
            .stdout = stdout,
            .stderr = stderr,
        };
    }
};

// The remainder of this file implements the namespaced executor with direct
// Linux system calls, replacing the previous setsid/unshare/mount/umount
// helper processes.

const child_stack_size: usize = 128 * 1024;
const guest_kill_grace_ms: u64 = 5 * 1000;
/// _LINUX_CAPABILITY_VERSION_3, the 64-bit capability ABI used by capset(2).
const linux_capability_version_3: u32 = 0x20080522;
const namespace_setup_failure_exit: u8 = 125;
const namespace_supervisor_failure_exit: u8 = 125;
const guest_exec_failure_exit: u8 = 126;
const guest_timeout_exit: u8 = 124;

/// Immutable description of the namespace the init child must build.  It lives
/// on the parent's stack and is read by the child through copy-on-write memory.
const NamespaceRequest = struct {
    root_fd: i32,
    root_fd_path: [*:0]const u8,
    mountpoint: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    guest_timeout_ms: u64,
    kill_grace_ms: u64,
    pre_chroot_delay_ms: u64,
    stdin_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
};

/// Parent-side handle to the cloned init child and the pipe read ends it feeds.
const SupervisedChild = struct {
    pid: i32,
    stdout: Io.File,
    stderr: Io.File,
    streams_open: bool = true,

    fn closeStreams(self: *SupervisedChild, io: Io) void {
        if (!self.streams_open) return;
        self.streams_open = false;
        self.stdout.close(io);
        self.stderr.close(io);
    }
};

const MountSpec = struct {
    source: [*:0]const u8,
    target: [*:0]const u8,
    fstype: [*:0]const u8,
    flags: u32,
    data: ?[*:0]const u8,
    stage: [*:0]const u8,
};

const DeviceNode = struct {
    path: [*:0]const u8,
    major: u32,
    minor: u32,
};

/// The pseudo-filesystem allowlist, byte-for-byte equivalent to the previous
/// in-namespace mount script.
const guest_mounts = [_]MountSpec{
    .{ .source = "proc", .target = "/proc", .fstype = "proc", .flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, .data = null, .stage = "proc" },
    .{ .source = "sysfs", .target = "/sys", .fstype = "sysfs", .flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, .data = null, .stage = "sys" },
    .{ .source = "tmpfs", .target = "/dev", .fstype = "tmpfs", .flags = linux.MS.NOSUID, .data = "mode=0755", .stage = "dev" },
    .{ .source = "tmpfs", .target = "/run", .fstype = "tmpfs", .flags = linux.MS.NOSUID | linux.MS.NODEV, .data = "mode=0755", .stage = "run" },
    .{ .source = "tmpfs", .target = "/tmp", .fstype = "tmpfs", .flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, .data = "mode=1777", .stage = "tmp" },
};

/// The device-node allowlist mirrors the previous `mknod` invocations.
const guest_devices = [_]DeviceNode{
    .{ .path = "/dev/null", .major = 1, .minor = 3 },
    .{ .path = "/dev/zero", .major = 1, .minor = 5 },
    .{ .path = "/dev/random", .major = 1, .minor = 8 },
    .{ .path = "/dev/urandom", .major = 1, .minor = 9 },
};

fn dupeArgvZ(arena: Allocator, argv: []const []const u8) ![:null]const ?[*:0]const u8 {
    const list = try arena.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |value, index| list[index] = (try arena.dupeZ(u8, value)).ptr;
    return list;
}

fn buildGuestEnvironment(arena: Allocator) ![:null]const ?[*:0]const u8 {
    const entries = [_][]const u8{
        "HOME=/root",
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM=dumb",
        "DEBIAN_FRONTEND=noninteractive",
    };
    const list = try arena.allocSentinel(?[*:0]const u8, entries.len, null);
    inline for (entries, 0..) |value, index| list[index] = (try arena.dupeZ(u8, value)).ptr;
    return list;
}

fn openChildPipe() ![2]i32 {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS)
        return error.PipeCreationFailed;
    return fds;
}

fn closePipePair(fds: [2]i32) void {
    _ = linux.close(fds[0]);
    _ = linux.close(fds[1]);
}

fn makeDevice(major: u32, minor: u32) u32 {
    return (major << 8) | (minor & 0xff) | ((minor & 0xffffff00) << 12);
}

/// Entry point for the cloned namespace init (PID 1).  It runs single-threaded
/// on a private stack, a copy-on-write image of the parent, so it must only use
/// async-signal-safe raw syscalls: no allocation, locks, TLS or panics.
fn namespaceChild(arg: usize) callconv(.c) u8 {
    const request: *const NamespaceRequest = @ptrFromInt(arg);

    // If the supervising parent dies, take the whole namespace down with it.
    // This replaces `unshare --kill-child`.
    _ = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @as(usize, @intFromEnum(linux.SIG.KILL)), 0, 0, 0);
    // Lead a fresh session/process group so the parent can signal the whole
    // tree at once (previously provided by `setsid`).
    _ = linux.setsid();
    resetChildSignals();

    // Attach the guest's stdio before the inherited descriptor table is closed.
    if (linux.errno(linux.dup2(request.stdin_fd, 0)) != .SUCCESS) return childSetupFailure("stdin");
    if (linux.errno(linux.dup2(request.stdout_fd, 1)) != .SUCCESS) return childSetupFailure("stdout");
    if (linux.errno(linux.dup2(request.stderr_fd, 2)) != .SUCCESS) return childSetupFailure("stderr");

    // Make every mount private so nothing propagates back to the host mount
    // namespace (previously `unshare --propagation private`).
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS)
        return childSetupFailure("propagation");

    if (request.pre_chroot_delay_ms != 0) childSleepMs(request.pre_chroot_delay_ms);

    // Re-resolve the staging root strictly through the inherited descriptor.
    // The kernel refuses to bind-mount the `/proc/self/fd/N` symlink target
    // directly (it returns EINVAL), so the path the descriptor currently names
    // is read back and bind-mounted onto a dedicated mountpoint inside this
    // private namespace; chrooting into a real mount root is what lets the
    // pseudo-filesystems below be mounted.  This mirrors the previous
    // `mount --bind /proc/self/fd/$root_fd $mountpoint` step.
    //
    // readlink followed by mount is a two-step path lookup, so a concurrent
    // rename or replacement between them could bind a different inode than the
    // one the parent opened.  Capture the inherited descriptor's identity first
    // and re-verify it after the bind: a bind mount exposes the source inode
    // unchanged, so the mountpoint must report the same device and inode and
    // must still be a directory.  Any mismatch is detached and fails closed
    // before the chroot can commit to the wrong tree.
    var root_identity: linux.Statx = undefined;
    if (linux.errno(linux.statx(request.root_fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &root_identity)) != .SUCCESS)
        return childSetupFailure("stat-root");

    var resolved_root: [linux.PATH_MAX]u8 = undefined;
    const link_len = linux.readlink(request.root_fd_path, &resolved_root, resolved_root.len);
    if (linux.errno(link_len) != .SUCCESS or link_len >= resolved_root.len)
        return childSetupFailure("resolve-root");
    resolved_root[link_len] = 0;
    const resolved_root_z: [*:0]const u8 = @ptrCast(&resolved_root);
    if (linux.errno(linux.mount(resolved_root_z, request.mountpoint, null, linux.MS.BIND, 0)) != .SUCCESS)
        return childSetupFailure("bind-root");

    var bound_identity: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, request.mountpoint, linux.AT.NO_AUTOMOUNT, linux.STATX.BASIC_STATS, &bound_identity)) != .SUCCESS or
        bound_identity.ino != root_identity.ino or
        bound_identity.dev_major != root_identity.dev_major or
        bound_identity.dev_minor != root_identity.dev_minor or
        (bound_identity.mode & linux.S.IFMT) != linux.S.IFDIR)
    {
        _ = linux.umount2(request.mountpoint, linux.MNT.DETACH);
        return childSetupFailure("verify-root");
    }

    if (linux.errno(linux.chroot(request.mountpoint)) != .SUCCESS) return childSetupFailure("chroot");
    if (linux.errno(linux.chdir("/")) != .SUCCESS) return childSetupFailure("chdir");
    _ = linux.close(request.root_fd);

    for (guest_mounts) |spec| {
        _ = linux.mkdir(spec.target, 0o755);
        const data: usize = if (spec.data) |ptr| @intFromPtr(ptr) else 0;
        if (linux.errno(linux.mount(spec.source, spec.target, spec.fstype, spec.flags, data)) != .SUCCESS)
            return childSetupFailure(spec.stage);
    }

    for (guest_devices) |device| {
        const mode: u32 = linux.S.IFCHR | 0o666;
        if (linux.errno(linux.mknod(device.path, mode, makeDevice(device.major, device.minor))) != .SUCCESS)
            return childSetupFailure("device");
        _ = linux.chmod(device.path, 0o666);
    }

    // Drop every inherited descriptor above stdio so the guest starts from a
    // clean table and can never observe the staging root descriptor.
    _ = linux.close_range(3, std.math.maxInt(i32), .{ .CLOEXEC = false, .UNSHARE = false });

    const guest = linux.fork();
    if (linux.errno(guest) != .SUCCESS) return childSetupFailure("fork");
    if (guest == 0) {
        // Guest child: drop all capabilities, then exec the allowlisted command
        // as an unprivileged (capability-empty) uid 0 process.
        dropAllCapabilities();
        const path = request.argv[0] orelse linux.exit(guest_exec_failure_exit);
        _ = linux.execve(path, request.argv, request.envp);
        childWriteAll(2, "vmiz-offline-root: exec failed\n");
        linux.exit(guest_exec_failure_exit);
    }

    return superviseGuest(@intCast(guest), request.guest_timeout_ms, request.kill_grace_ms);
}

/// Reset the signals PID 1 relies on so an inherited disposition cannot disturb
/// child reaping or teardown signalling.
fn resetChildSignals() void {
    const action = linux.Sigaction{
        .handler = .{ .handler = linux.SIG.DFL },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.CHLD, &action, null);
    const empty = std.mem.zeroes(linux.sigset_t);
    _ = linux.sigprocmask(linux.SIG.SETMASK, &empty, null);
}

/// Supervise the guest from inside the namespace: enforce the per-command
/// timeout, escalate TERM then KILL, and reap every descendant so no zombie or
/// stray process survives.  Runs as PID 1, so `kill(-1, ...)` reaches the whole
/// namespace exactly like the previous `kill -KILL -1`.
fn superviseGuest(guest_pid: i32, timeout_ms: u64, kill_grace_ms: u64) u8 {
    const start = monotonicMs();
    var guest_status: u32 = 0;
    var guest_reaped = false;
    var timed_out = false;
    var escalated = false;
    var terminate_at: u64 = 0;
    while (true) {
        while (true) {
            var status: u32 = undefined;
            const rc = linux.waitpid(-1, &status, linux.W.NOHANG);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) break;
                    if (@as(i32, @intCast(rc)) == guest_pid) {
                        guest_status = status;
                        guest_reaped = true;
                    }
                },
                .INTR => {},
                .CHILD => {
                    if (timed_out) return guest_timeout_exit;
                    if (guest_reaped) return exitStatusCode(guest_status);
                    return namespace_supervisor_failure_exit;
                },
                else => return namespace_supervisor_failure_exit,
            }
        }
        const now = monotonicMs();
        if (guest_reaped) {
            _ = linux.kill(-1, linux.SIG.KILL);
        } else if (!timed_out and now -% start >= timeout_ms) {
            timed_out = true;
            terminate_at = now;
            _ = linux.kill(-1, linux.SIG.TERM);
        } else if (timed_out and !escalated and now -% terminate_at >= kill_grace_ms) {
            escalated = true;
            _ = linux.kill(-1, linux.SIG.KILL);
        }
        childSleepMs(10);
    }
}

/// Replicates `setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all`:
/// clears the ambient set, empties the bounding set, and zeroes the permitted,
/// effective and inheritable sets so the exec starts with no capabilities.
fn dropAllCapabilities() void {
    _ = linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    var capability: usize = 0;
    while (capability <= linux.CAP.LAST_CAP) : (capability += 1) {
        _ = linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), capability, 0, 0, 0);
    }
    var header = linux.cap_user_header_t{ .version = linux_capability_version_3, .pid = 0 };
    const data = [2]linux.cap_user_data_t{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    _ = linux.capset(&header, &data[0]);
}

fn childSleepMs(milliseconds: u64) void {
    var request = linux.timespec{
        .sec = @intCast(milliseconds / 1000),
        .nsec = @intCast((milliseconds % 1000) * std.time.ns_per_ms),
    };
    var remaining: linux.timespec = undefined;
    while (true) {
        const rc = linux.nanosleep(&request, &remaining);
        if (linux.errno(rc) == .INTR) {
            request = remaining;
            continue;
        }
        return;
    }
}

fn monotonicMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    const seconds: u64 = if (ts.sec < 0) 0 else @intCast(ts.sec);
    const nanoseconds: u64 = if (ts.nsec < 0) 0 else @intCast(ts.nsec);
    return seconds *% 1000 +% nanoseconds / std.time.ns_per_ms;
}

fn exitStatusCode(status: u32) u8 {
    const signal = status & 0x7f;
    if (signal == 0) return @intCast((status >> 8) & 0xff);
    return @intCast(128 + (signal & 0x7f));
}

fn childSetupFailure(stage: [*:0]const u8) u8 {
    childWriteAll(2, "vmiz-offline-root: setup stage '");
    childWriteAll(2, std.mem.span(stage));
    childWriteAll(2, "' failed\n");
    return namespace_setup_failure_exit;
}

fn childWriteAll(fd: i32, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return;
                offset += rc;
            },
            .INTR => {},
            else => return,
        }
    }
}

fn signalChildTree(pid: i32) void {
    if (comptime builtin.os.tag != .linux) return;
    _ = linux.kill(-pid, linux.SIG.TERM);
    _ = linux.kill(pid, linux.SIG.TERM);
    _ = linux.kill(-pid, linux.SIG.KILL);
    _ = linux.kill(pid, linux.SIG.KILL);
}

fn reapChild(pid: i32) void {
    if (comptime builtin.os.tag != .linux) return;
    var status: u32 = undefined;
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        if (linux.errno(rc) == .INTR) continue;
        return;
    }
}

fn makeSupervisorDeadline(io: Io, timeout_ms: u64) !Io.Timeout {
    const milliseconds = std.math.cast(i64, timeout_ms) orelse return error.TimeoutOutOfRange;
    return (Io.Timeout{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(milliseconds),
        .clock = .awake,
    } }).toDeadline(io);
}

fn waitUntilDeadline(
    io: Io,
    pid: i32,
    deadline: Io.Timeout,
    mode: PidfdMode,
    pidfd_open_fn: ?PidfdOpenFn,
) !std.process.Child.Term {
    if (comptime builtin.os.tag != .linux) return error.Timeout;
    if (mode == .force_unexpected) return error.PidfdSetupFailed;
    if (mode != .auto) return waitpidFallback(io, pid, deadline);
    const opened = if (pidfd_open_fn) |open_fn|
        open_fn(pid)
    else
        linux.pidfd_open(pid, 0);
    if (linux.errno(opened) != .SUCCESS) switch (linux.errno(opened)) {
        .NOSYS, .INVAL, .PERM, .MFILE, .NFILE => return waitpidFallback(io, pid, deadline),
        else => return error.PidfdSetupFailed,
    };
    const pidfd: i32 = @intCast(opened);
    defer _ = linux.close(pidfd);
    while (true) {
        const remaining = deadline.toDurationFromNow(io) orelse return reapTerm(pid);
        if (remaining.raw.nanoseconds <= 0) return error.Timeout;
        var fds = [_]linux.pollfd{.{
            .fd = pidfd,
            .events = linux.POLL.IN,
            .revents = 0,
        }};
        const milliseconds = @max(@as(i64, 1), remaining.raw.toMilliseconds());
        const poll_result = linux.poll(&fds, fds.len, @intCast(@min(milliseconds, std.math.maxInt(i32))));
        switch (linux.errno(poll_result)) {
            .SUCCESS => if (poll_result != 0) return reapTerm(pid),
            .INTR => {},
            else => return waitpidFallback(io, pid, deadline),
        }
    }
}

fn waitpidFallback(io: Io, pid: i32, deadline: Io.Timeout) !std.process.Child.Term {
    while (true) {
        const remaining = deadline.toDurationFromNow(io) orelse return reapTerm(pid);
        if (remaining.raw.nanoseconds <= 0) return error.Timeout;
        var status: u32 = undefined;
        const result = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result != 0) return waitStatusTerm(status);
            },
            .INTR => continue,
            else => return error.WaitpidFailed,
        }
        const sleep_ns = @min(
            remaining.raw.nanoseconds,
            @as(i96, 10 * std.time.ns_per_ms),
        );
        try Io.sleep(io, Io.Duration.fromNanoseconds(sleep_ns), .awake);
    }
}

fn reapTerm(pid: i32) std.process.Child.Term {
    var status: u32 = undefined;
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        if (linux.errno(rc) == .INTR) continue;
        break;
    }
    return waitStatusTerm(status);
}

fn waitStatusTerm(status: u32) std.process.Child.Term {
    const signal = status & 0x7f;
    if (signal == 0) return .{ .exited = @intCast((status >> 8) & 0xff) };
    if (signal == 0x7f) return .{ .stopped = @enumFromInt(@as(u8, @intCast((status >> 8) & 0xff))) };
    return .{ .signal = @enumFromInt(@as(u8, @intCast(signal))) };
}

pub const Root = struct {
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    root_dir: Io.Dir,
    root_inode: Io.File.INode,
    limits: Limits = .{},

    pub fn init(allocator: Allocator, io: Io, root_path: []const u8, limits: Limits) !Root {
        if (!std.fs.path.isAbsolute(root_path)) return error.RootPathMustBeAbsolute;
        var root_dir = try openRootPathNoFollow(io, root_path);
        errdefer root_dir.close(io);
        const stat = try root_dir.stat(io);
        if (stat.kind != .directory) return error.RootNotDirectory;
        return .{
            .allocator = allocator,
            .io = io,
            .root_path = root_path,
            .root_dir = root_dir,
            .root_inode = stat.inode,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Root) void {
        self.root_dir.close(self.io);
        self.* = undefined;
    }

    pub fn apply(self: *Root, operations: []const Operation) !void {
        for (operations) |operation| try self.applyOne(operation);
    }

    pub fn applyOne(self: *Root, operation: Operation) !void {
        switch (operation) {
            .write_file => |file| try self.writeFile(file),
            .create_directory => |directory| try self.createDirectory(directory.path, directory.mode),
            .replace_symlink => |link| try self.replaceSymlink(link.path, link.target),
            .remove => |path| self.remove(path, true) catch |err| switch (err) {
                error.PathNotFound => {},
                else => return err,
            },
            .cleanup => |cleanup_op| try self.cleanup(cleanup_op.directory, cleanup_op.pattern),
        }
    }

    pub fn writeFile(self: *Root, file: WriteFile) !void {
        const relative = try normalizeGuestPath(file.path);
        var bytes: []u8 = undefined;
        var owned = false;
        switch (file.source) {
            .inline_bytes => |value| {
                if (value.len > self.limits.max_file_bytes) return error.FileLimitExceeded;
                bytes = @constCast(value);
            },
            .host_path => |source| {
                bytes = try Io.Dir.cwd().readFileAlloc(self.io, source, self.allocator, .limited(self.limits.max_file_bytes));
                owned = true;
            },
        }
        defer if (owned) self.allocator.free(bytes);
        var parent = try self.openParentDirectory(relative, true);
        defer parent.dir.close(self.io);
        const existing = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch null;
        if (existing) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            try parent.dir.deleteFile(self.io, parent.name);
        }
        try parent.dir.writeFile(self.io, .{
            .sub_path = parent.name,
            .data = bytes,
            .flags = .{
                .exclusive = true,
                .permissions = .fromMode(file.mode),
                .resolve_beneath = true,
            },
        });
    }

    pub fn createDirectory(self: *Root, guest_path: []const u8, mode: u32) !void {
        const relative = try normalizeGuestPath(guest_path);
        var directory = try self.openDirectoryPath(relative, true);
        defer directory.close(self.io);
        try directory.setPermissions(self.io, .fromMode(mode));
    }

    pub fn replaceSymlink(self: *Root, guest_path: []const u8, target: []const u8) !void {
        if (target.len == 0 or std.mem.indexOfScalar(u8, target, 0) != null) return error.InvalidSymlinkTarget;
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, true);
        defer parent.dir.close(self.io);
        if (parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            try parent.dir.deleteFile(self.io, parent.name);
        } else |_| {}
        try parent.dir.symLink(self.io, target, parent.name, .{});
    }

    pub fn remove(self: *Root, guest_path: []const u8, recursive: bool) !void {
        const relative = try normalizeGuestPath(guest_path);
        var parent = self.openParentDirectory(relative, false) catch |err| switch (err) {
            error.FileNotFound => return error.PathNotFound,
            else => return err,
        };
        defer parent.dir.close(self.io);
        const stat = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch
            return error.PathNotFound;
        if (stat.kind == .directory and recursive) {
            try parent.dir.deleteTree(self.io, parent.name);
        } else {
            try parent.dir.deleteFile(self.io, parent.name);
        }
    }

    pub fn cleanup(self: *Root, guest_directory: []const u8, pattern: []const u8) !void {
        const entries = self.discover(guest_directory, pattern) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.freeFound(entries);
        for (entries) |entry| try self.remove(entry.path, true);
    }

    pub fn discover(self: *Root, guest_directory: []const u8, pattern: []const u8) ![]FoundEntry {
        if (std.mem.count(u8, pattern, "*") > 1) return error.InvalidDiscoveryPattern;
        const relative = try normalizeGuestPath(guest_directory);
        var dir = try self.openDirectoryPath(relative, false);
        defer dir.close(self.io);
        var iterator = dir.iterate();
        var entries = std.array_list.Managed(FoundEntry).init(self.allocator);
        errdefer {
            for (entries.items) |entry| self.allocator.free(entry.path);
            entries.deinit();
        }
        while (try iterator.next(self.io)) |entry| {
            if (entries.items.len >= self.limits.max_entries) return error.EntryLimitExceeded;
            if (!wildcardMatch(pattern, entry.name)) continue;
            const path = if (std.mem.eql(u8, guest_directory, "/"))
                try std.fmt.allocPrint(self.allocator, "/{s}", .{entry.name})
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ guest_directory, entry.name });
            try entries.append(.{ .path = path, .directory = entry.kind == .directory });
        }
        return entries.toOwnedSlice();
    }

    pub fn freeFound(self: *Root, entries: []const FoundEntry) void {
        for (entries) |entry| self.allocator.free(entry.path);
        self.allocator.free(entries);
    }

    pub fn inspect(self: *Root, guest_path: []const u8) !Inspection {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        const stat = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return error.PathNotFound,
            else => return err,
        };
        return .{
            .path = try self.allocator.dupe(u8, guest_path),
            .kind = switch (stat.kind) {
                .file => .file,
                .directory => .directory,
                .sym_link => .symlink,
                else => .other,
            },
            .size = stat.size,
        };
    }

    pub fn readFile(self: *Root, guest_path: []const u8) ![]u8 {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        var file = try parent.dir.openFile(self.io, parent.name, .{
            .mode = .read_only,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegularFile;
        if (stat.size > self.limits.max_file_bytes) return error.FileLimitExceeded;
        const bytes = try self.allocator.alloc(u8, @intCast(stat.size));
        errdefer self.allocator.free(bytes);
        _ = try file.readPositionalAll(self.io, bytes, 0);
        return bytes;
    }

    pub fn readLink(self: *Root, guest_path: []const u8) ![]u8 {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try parent.dir.readLink(self.io, parent.name, &buffer);
        return self.allocator.dupe(u8, buffer[0..length]);
    }

    pub fn validateArchitecture(self: *Root, architecture: Architecture) !void {
        const shell = self.readFile("/usr/bin/dash") catch return error.GuestArchitectureUnknown;
        defer self.allocator.free(shell);
        if (shell.len < 20 or !std.mem.eql(u8, shell[0..4], "\x7fELF")) {
            return error.GuestArchitectureUnknown;
        }
        const machine = std.mem.readInt(u16, shell[18..20], .little);
        const expected: u16 = switch (architecture) {
            .x86_64 => 62,
            .aarch64 => 183,
        };
        if (machine != expected) return error.ArchitectureMismatch;
    }

    pub fn extract(self: *Root, guest_path: []const u8, host_path: []const u8) !void {
        const bytes = try self.readFile(guest_path);
        defer self.allocator.free(bytes);
        try Io.Dir.cwd().writeFile(self.io, .{ .sub_path = host_path, .data = bytes });
    }

    pub fn insert(self: *Root, host_path: []const u8, guest_path: []const u8, mode: u32) !void {
        try self.writeFile(.{ .path = guest_path, .source = .{ .host_path = host_path }, .mode = mode });
    }

    /// The release named by `/boot/vmlinuz`, required to be the kernel flavor
    /// the caller asked for.
    ///
    /// The suffix is a parameter rather than a constant because which kernel
    /// is the right one is a property of the image being built, not of this
    /// library: an Azure image must boot `-azure`, and an image for a
    /// particular machine must boot the kernel that machine's hardware is
    /// supported by. Accepting whatever happens to be in `/boot` would let a
    /// wrong kernel through silently, which is the failure this check exists
    /// to prevent.
    pub fn activeKernelRelease(self: *Root, suffix: []const u8) ![]u8 {
        const target = try self.readLink("/boot/vmlinuz");
        defer self.allocator.free(target);
        const name = std.fs.path.basename(target);
        if (!std.mem.startsWith(u8, name, "vmlinuz-") or !std.mem.endsWith(u8, name, suffix))
            return error.ExpectedKernelMissing;
        return self.allocator.dupe(u8, name["vmlinuz-".len..]);
    }

    pub fn duplicateDir(self: *const Root) !Io.Dir {
        const duplicate = if (comptime builtin.os.tag == .linux) blk: {
            const result = std.os.linux.fcntl(
                self.root_dir.handle,
                std.os.linux.F.DUPFD,
                128,
            );
            if (@as(isize, @bitCast(result)) < 0) return error.RootFdDupFailed;
            break :blk Io.Dir{ .handle = @intCast(result) };
        } else try self.root_dir.openDir(self.io, ".", .{
            .access_sub_paths = true,
            .iterate = true,
            .follow_symlinks = false,
        });
        const stat = duplicate.stat(self.io) catch |err| {
            duplicate.close(self.io);
            return err;
        };
        if (stat.kind != .directory or stat.inode != self.root_inode) {
            duplicate.close(self.io);
            return error.RootDescriptorChanged;
        }
        return duplicate;
    }

    fn openDirectoryPath(self: *Root, relative: []const u8, create_missing: bool) !Io.Dir {
        var current = try self.duplicateDir();
        if (relative.len == 0) return current;
        var components = std.mem.splitScalar(u8, relative, '/');
        while (components.next()) |component| {
            const stat = current.statFile(self.io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => if (create_missing) blk: {
                    try current.createDir(self.io, component, .default_dir);
                    break :blk try current.statFile(self.io, component, .{ .follow_symlinks = false });
                } else {
                    current.close(self.io);
                    return err;
                },
                else => {
                    current.close(self.io);
                    return err;
                },
            };
            if (stat.kind != .directory) {
                current.close(self.io);
                return error.NotDirectory;
            }
            const next = current.openDir(self.io, component, .{
                .access_sub_paths = true,
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                current.close(self.io);
                return err;
            };
            current.close(self.io);
            current = next;
        }
        return current;
    }

    fn openParentDirectory(self: *Root, relative: []const u8, create_missing: bool) !ParentDirectory {
        if (relative.len == 0) return error.InvalidGuestPath;
        const parent = std.fs.path.dirname(relative) orelse "";
        return .{
            .dir = try self.openDirectoryPath(parent, create_missing),
            .name = std.fs.path.basename(relative),
        };
    }
};

fn commandTimeoutMs(command: Command) u64 {
    return switch (command) {
        .update_initramfs => 300 * 1000,
        .dpkg_query => 60 * 1000,
        .cloud_init_clean => 30 * 1000,
    };
}

fn commandArgCount(command: Command) usize {
    return switch (command) {
        .update_initramfs => 4,
        .dpkg_query => 3,
        .cloud_init_clean => |options| 2 + @as(usize, @intFromBool(options.logs)),
    };
}

fn validateToken(value: []const u8, err: anyerror) !void {
    if (value.len == 0 or value.len > 128) return err;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and byte != '_' and byte != '+' and byte != '-' and byte != '@')
            return err;
    }
}

fn normalizeGuestPath(path: []const u8) ![]const u8 {
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidGuestPath;
    if (std.mem.eql(u8, path, "/")) return path[1..];
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidGuestPath;
    }
    return path[1..];
}

fn wildcardMatch(pattern: []const u8, value: []const u8) bool {
    if (std.mem.indexOfScalar(u8, pattern, '*')) |index| {
        return std.mem.startsWith(u8, value, pattern[0..index]) and
            std.mem.endsWith(u8, value, pattern[index + 1 ..]) and
            value.len >= pattern.len - 1;
    }
    return std.mem.eql(u8, pattern, value);
}

fn openRootPathNoFollow(io: Io, absolute_path: []const u8) !Io.Dir {
    var current = try Io.Dir.openDirAbsolute(io, "/", .{
        .access_sub_paths = true,
        .iterate = true,
        .follow_symlinks = false,
    });
    var components = std.mem.splitScalar(u8, absolute_path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            current.close(io);
            return error.InvalidRootPath;
        }
        const next = current.openDir(io, component, .{
            .access_sub_paths = true,
            .iterate = true,
            .follow_symlinks = false,
        }) catch |err| {
            current.close(io);
            return err;
        };
        current.close(io);
        current = next;
    }
    return current;
}

fn expectNoResidualOfflineMounts(io: Io) !void {
    var run_dir = try Io.Dir.openDirAbsolute(io, "/run", .{ .iterate = true });
    defer run_dir.close(io);
    var iterator = run_dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (std.mem.startsWith(u8, entry.name, "vmiz-offline-root-"))
            return error.OfflineRootMountpointResidual;
    }
}

fn countOpenFds(io: Io) !usize {
    var fd_dir = try Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer fd_dir.close(io);
    var iterator = fd_dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |_| count += 1;
    return count;
}

test "offline root rejects traversal and wildcard ambiguity" {
    try std.testing.expectError(error.InvalidGuestPath, normalizeGuestPath("/etc/../shadow"));
    try std.testing.expectError(error.InvalidDiscoveryPattern, blk: {
        var root = Root{
            .allocator = std.testing.allocator,
            .io = undefined,
            .root_path = "/",
            .root_dir = undefined,
            .root_inode = undefined,
        };
        break :blk root.discover("/", "a*b*c");
    });
}

test "offline command validation is fail closed" {
    try std.testing.expectError(error.InvalidKernelRelease, blk: {
        var executor = Executor{
            .allocator = std.testing.allocator,
            .io = undefined,
            .options = .{
                .root = undefined,
                .architecture = Architecture.host(),
                .require_privileged_namespace = false,
            },
            .root_dir = undefined,
            .root_inode = undefined,
            .root_dir_owned = false,
            .records = .init(std.testing.allocator),
        };
        defer executor.deinit();
        var args = std.array_list.Managed([]const u8).init(std.testing.allocator);
        defer args.deinit();
        break :blk executor.appendCommand(&args, .{ .update_initramfs = "../bad" });
    });
}

test "offline root initialization rejects a symlinked root path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const target = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-target" });
    defer allocator.free(target);
    const link = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-link" });
    defer allocator.free(link);
    Io.Dir.cwd().deleteTree(io, target) catch {};
    Io.Dir.cwd().deleteFile(io, link) catch {};
    defer Io.Dir.cwd().deleteTree(io, target) catch {};
    defer Io.Dir.cwd().deleteFile(io, link) catch {};
    try Io.Dir.cwd().createDirPath(io, target);
    try Io.Dir.cwd().symLink(io, target, link, .{});
    const opened = Root.init(allocator, io, link, .{}) catch |err| {
        try std.testing.expect(err == error.NotDir or err == error.SymLinkLoop or err == error.GuestSymlinkTraversal);
        return;
    };
    var accepted = opened;
    accepted.deinit();
    return error.RootSymlinkAccepted;
}

const RootInitRace = struct {
    link: []const u8,
    outside: []const u8,
    stop: *std.atomic.Value(bool),
    io: Io,

    fn run(self: *RootInitRace) void {
        while (!self.stop.load(.acquire)) {
            Io.Dir.cwd().deleteTree(self.io, self.link) catch {};
            Io.Dir.cwd().symLink(self.io, self.outside, self.link, .{}) catch {};
            Io.Dir.cwd().deleteFile(self.io, self.link) catch {};
            Io.Dir.cwd().createDirPath(self.io, self.link) catch {};
        }
    }
};

test "offline root init never follows a concurrently replaced root path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const target = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-target" });
    defer allocator.free(target);
    const outside = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-outside" });
    defer allocator.free(outside);
    const link = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-link" });
    defer allocator.free(link);
    Io.Dir.cwd().deleteTree(io, target) catch {};
    Io.Dir.cwd().deleteTree(io, outside) catch {};
    Io.Dir.cwd().deleteTree(io, link) catch {};
    defer Io.Dir.cwd().deleteTree(io, target) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside) catch {};
    defer Io.Dir.cwd().deleteTree(io, link) catch {};
    try Io.Dir.cwd().createDirPath(io, target);
    try Io.Dir.cwd().createDirPath(io, outside);
    try Io.Dir.cwd().createDirPath(io, link);
    const outside_stat = try Io.Dir.cwd().statFile(io, outside, .{ .follow_symlinks = false });

    var stop = std.atomic.Value(bool).init(false);
    var race = RootInitRace{ .link = link, .outside = outside, .stop = &stop, .io = io };
    var thread = try std.Thread.spawn(.{}, RootInitRace.run, .{&race});
    for (0..128) |_| {
        if (Root.init(allocator, io, link, .{})) |opened| {
            var root = opened;
            if (root.root_inode == outside_stat.inode) {
                root.deinit();
                stop.store(true, .release);
                thread.join();
                return error.RootInitEscapedToOutside;
            }
            root.deinit();
        } else |_| {}
    }
    stop.store(true, .release);
    thread.join();
}

test "offline root applies structured operations and cleans up" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-operations" });
    defer allocator.free(path);
    Io.Dir.cwd().deleteTree(io, path) catch {};
    defer Io.Dir.cwd().deleteTree(io, path) catch {};
    const etc = try std.fs.path.join(allocator, &.{ path, "etc" });
    defer allocator.free(etc);
    const logs = try std.fs.path.join(allocator, &.{ path, "var/log" });
    defer allocator.free(logs);
    const stale = try std.fs.path.join(allocator, &.{ logs, "stale" });
    defer allocator.free(stale);
    try Io.Dir.cwd().createDirPath(io, etc);
    try Io.Dir.cwd().createDirPath(io, logs);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = stale, .data = "stale" });

    var root = try Root.init(allocator, io, path, .{});
    defer root.deinit();
    try root.apply(&.{
        .{ .create_directory = .{ .path = "/etc/vmiz", .mode = 0o755 } },
        .{ .write_file = .{ .path = "/etc/vmiz/config", .source = .{ .inline_bytes = "ok\n" } } },
        .{ .replace_symlink = .{ .path = "/etc/vmiz/current", .target = "/etc/vmiz/config" } },
    });
    const config = try root.readFile("/etc/vmiz/config");
    defer allocator.free(config);
    try std.testing.expectEqualStrings("ok\n", config);
    const link = try root.readLink("/etc/vmiz/current");
    defer allocator.free(link);
    try std.testing.expectEqualStrings("/etc/vmiz/config", link);
    const found = try root.discover("/etc/vmiz", "*");
    defer root.freeFound(found);
    try std.testing.expectEqual(@as(usize, 2), found.len);
    try root.cleanup("/var/log", "*");
    try std.testing.expectError(error.PathNotFound, root.inspect("/var/log/stale"));
}

test "offline root refuses intermediate symlink escapes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-symlink-root" });
    defer allocator.free(root_path);
    const outside_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-symlink-outside" });
    defer allocator.free(outside_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    const safe_path = try std.fs.path.join(allocator, &.{ root_path, "safe" });
    defer allocator.free(safe_path);
    try Io.Dir.cwd().createDirPath(io, safe_path);
    try Io.Dir.cwd().createDirPath(io, outside_path);
    const sentinel = try std.fs.path.join(allocator, &.{ outside_path, "sentinel" });
    defer allocator.free(sentinel);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "unchanged" });

    const etc_path = try std.fs.path.join(allocator, &.{ root_path, "etc" });
    defer allocator.free(etc_path);
    try Io.Dir.cwd().symLink(io, outside_path, etc_path, .{});
    const nested_path = try std.fs.path.join(allocator, &.{ root_path, "safe/nested" });
    defer allocator.free(nested_path);
    try Io.Dir.cwd().symLink(io, outside_path, nested_path, .{});

    var root = try Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    for ([_][]const u8{ "/etc/escape", "/safe/nested/escape" }) |guest_path| {
        root.writeFile(.{
            .path = guest_path,
            .source = .{ .inline_bytes = "must-not-write" },
        }) catch |err| {
            try std.testing.expect(
                err == error.NotDir or
                    err == error.NotDirectory or
                    err == error.GuestSymlinkTraversal or
                    err == error.SymLinkLoop,
            );
            continue;
        };
        return error.SymlinkEscapeAccepted;
    }
    const unchanged = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(unchanged);
    try std.testing.expectEqualStrings("unchanged", unchanged);
}

const SymlinkRace = struct {
    root_path: []const u8,
    outside_path: []const u8,
    stop: *std.atomic.Value(bool),
    io: Io,

    fn run(self: *SymlinkRace) void {
        while (!self.stop.load(.acquire)) {
            const nested = std.fs.path.join(std.heap.page_allocator, &.{ self.root_path, "safe/nested" }) catch return;
            defer std.heap.page_allocator.free(nested);
            Io.Dir.cwd().deleteTree(self.io, nested) catch {};
            Io.Dir.cwd().symLink(self.io, self.outside_path, nested, .{}) catch {};
            Io.Dir.cwd().deleteFile(self.io, nested) catch {};
            Io.Dir.cwd().createDirPath(self.io, nested) catch {};
        }
    }
};

test "offline root mutations and discovery survive concurrent symlink replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-concurrent-root" });
    defer allocator.free(root_path);
    const outside_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-concurrent-outside" });
    defer allocator.free(outside_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    const safe_path = try std.fs.path.join(allocator, &.{ root_path, "safe" });
    defer allocator.free(safe_path);
    try Io.Dir.cwd().createDirPath(io, safe_path);
    try Io.Dir.cwd().createDirPath(io, outside_path);

    var root = try Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var race = SymlinkRace{
        .root_path = root_path,
        .outside_path = outside_path,
        .stop = &stop,
        .io = io,
    };
    var thread = try std.Thread.spawn(.{}, SymlinkRace.run, .{&race});
    for (0..128) |_| {
        root.writeFile(.{
            .path = "/safe/nested/file",
            .source = .{ .inline_bytes = "inside" },
        }) catch {};
        root.createDirectory("/safe/nested/mkdir", 0o755) catch {};
        root.replaceSymlink("/safe/nested/link", "/safe/nested/file") catch {};
        root.remove("/safe/nested/file", false) catch {};
        const entries = root.discover("/safe/nested", "*") catch null;
        if (entries) |found| root.freeFound(found);
    }
    stop.store(true, .release);
    thread.join();

    const outside_file = try std.fs.path.join(allocator, &.{ outside_path, "file" });
    defer allocator.free(outside_file);
    const outside_mkdir = try std.fs.path.join(allocator, &.{ outside_path, "mkdir" });
    defer allocator.free(outside_mkdir);
    const outside_link = try std.fs.path.join(allocator, &.{ outside_path, "link" });
    defer allocator.free(outside_link);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_file, .{ .follow_symlinks = false }));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_mkdir, .{ .follow_symlinks = false }));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_link, .{ .follow_symlinks = false }));
}

const FakeRunner = struct {
    outcome: CommandOutcome,
    exit_code: ?u8 = 0,
    saw_allowlisted: bool = false,
    timeout_ms: u64 = 0,

    fn run(
        context: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        argv: []const []const u8,
        timeout_ms: u64,
    ) !CommandResult {
        const self: *FakeRunner = @ptrCast(@alignCast(context.?));
        if (argv.len == 0) return error.EmptyCommand;
        self.saw_allowlisted = std.mem.eql(u8, argv[0], "/usr/bin/dpkg-query");
        self.timeout_ms = timeout_ms;
        return .{
            .outcome = self.outcome,
            .exit_code = self.exit_code,
            .stdout = try allocator.dupe(u8, ""),
            .stderr = try allocator.dupe(u8, ""),
        };
    }
};

fn fakePidfdErrno(errno: std.os.linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(errno))));
}

fn fakePidfdEnosys(_: i32) usize {
    return fakePidfdErrno(.NOSYS);
}
fn fakePidfdInval(_: i32) usize {
    return fakePidfdErrno(.INVAL);
}
fn fakePidfdPerm(_: i32) usize {
    return fakePidfdErrno(.PERM);
}
fn fakePidfdMfile(_: i32) usize {
    return fakePidfdErrno(.MFILE);
}
fn fakePidfdNfile(_: i32) usize {
    return fakePidfdErrno(.NFILE);
}
fn fakePidfdUnexpected(_: i32) usize {
    return fakePidfdErrno(.BADF);
}

test "offline executor enforces architecture, allowlist, timeout, and failure" {
    const host = Architecture.host();
    const foreign: Architecture = if (host == .x86_64) .aarch64 else .x86_64;
    var test_root = try Root.init(std.testing.allocator, std.testing.io, "/", .{});
    defer test_root.deinit();
    var invalid_override = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .supervisor_timeout_ms_override = std.math.maxInt(u64),
    });
    defer invalid_override.deinit();
    const before_invalid = try countOpenFds(std.testing.io);
    for (0..8) |_| {
        try std.testing.expectError(
            error.TimeoutOutOfRange,
            invalid_override.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, 1000),
        );
    }
    try std.testing.expectEqual(before_invalid, try countOpenFds(std.testing.io));
    var overflow_timeout = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
    });
    defer overflow_timeout.deinit();
    try std.testing.expectError(
        error.TimeoutOutOfRange,
        overflow_timeout.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, std.math.maxInt(u64)),
    );
    try std.testing.expectError(error.ArchitectureMismatch, Executor.init(
        std.testing.allocator,
        std.testing.io,
        .{
            .root = &test_root,
            .architecture = foreign,
            .require_privileged_namespace = false,
        },
    ));

    var success = FakeRunner{ .outcome = .succeeded };
    var executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &success,
    });
    defer executor.deinit();
    var result = try executor.execute(.dpkg_query);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(success.saw_allowlisted);
    try std.testing.expectEqual(@as(u64, 60 * 1000), success.timeout_ms);

    var timeout = FakeRunner{ .outcome = .timed_out };
    var timeout_executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &timeout,
    });
    defer timeout_executor.deinit();
    try std.testing.expectError(error.CommandTimeout, timeout_executor.execute(.{ .cloud_init_clean = .{} }));
    try std.testing.expectEqual(@as(u64, 30 * 1000), timeout.timeout_ms);

    var failure = FakeRunner{ .outcome = .failed, .exit_code = 2 };
    var failure_executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &failure,
    });
    defer failure_executor.deinit();
    try std.testing.expectError(error.CommandFailed, failure_executor.execute(.{ .update_initramfs = "6.0.0-azure" }));
    try std.testing.expectEqual(@as(u64, 300 * 1000), failure.timeout_ms);
}

test "privileged offline namespace contains PID1 and reaps descendants" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0) {
        std.debug.print("skipping offline-root containment test: root Linux runner required\n", .{});
        return;
    }
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const fixture = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-integration-root" });
    defer allocator.free(fixture);
    if (Io.Dir.cwd().statFile(io, fixture, .{ .follow_symlinks = false })) |_| {} else |_| {
        std.debug.print("skipping offline-root containment test: integration root fixture missing\n", .{});
        return;
    }
    var root = try Root.init(allocator, io, fixture, .{});
    defer root.deinit();
    const pinned = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-pinned" });
    defer allocator.free(pinned);
    Io.Dir.cwd().deleteTree(io, pinned) catch {};
    try Io.Dir.rename(Io.Dir.cwd(), fixture, Io.Dir.cwd(), pinned, io);
    try Io.Dir.cwd().symLink(io, cwd, fixture, .{});
    defer {
        Io.Dir.cwd().deleteFile(io, fixture) catch {};
        Io.Dir.rename(Io.Dir.cwd(), pinned, Io.Dir.cwd(), fixture, io) catch {};
    }
    const sentinel = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-host-sentinel" });
    defer allocator.free(sentinel);
    const marker = try std.fs.path.join(allocator, &.{ pinned, "descendant-marker" });
    defer allocator.free(marker);
    Io.Dir.cwd().deleteFile(io, sentinel) catch {};
    Io.Dir.cwd().deleteFile(io, marker) catch {};
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "unchanged" });
    defer Io.Dir.cwd().deleteFile(io, sentinel) catch {};

    var executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
    });
    defer executor.deinit();
    const probe = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "printf escaped > \"/proc/1/root$1\"", "probe", sentinel },
        5 * 1000,
    );
    defer {
        var result = probe;
        result.deinit(allocator);
    }
    const sentinel_bytes = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(sentinel_bytes);
    try std.testing.expectEqualStrings("unchanged", sentinel_bytes);
    try expectNoResidualOfflineMounts(io);
    const root_fd_text = try std.fmt.allocPrint(allocator, "{d}", .{executor.root_dir.handle});
    defer allocator.free(root_fd_text);
    const fd_probe = try executor.runIsolated(
        &.{
            "/bin/sh",
            "-c",
            "if [ -e \"/proc/self/fd/$1\" ] || [ -e \"/proc/self/fd/$1/..\" ]; then printf escaped > \"$2\"; fi; for fd in /proc/self/fd/*; do n=\"${fd##*/}\"; if [ \"$n\" = \"$1\" ]; then printf escaped > \"$2\"; fi; done",
            "fd-probe",
            root_fd_text,
            sentinel,
        },
        5 * 1000,
    );
    defer {
        var result = fd_probe;
        result.deinit(allocator);
    }
    const fd_sentinel = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(fd_sentinel);
    try std.testing.expectEqualStrings("unchanged", fd_sentinel);
    try expectNoResidualOfflineMounts(io);

    // Success path: an allowlisted guest command runs to completion inside the
    // namespace, and both its captured stdout and zero exit status are
    // reported back through the raw-syscall supervisor.
    const succeeded = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "printf 'ok-%s' \"$1\"", "vmiz", "42" },
        5 * 1000,
    );
    defer {
        var result = succeeded;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.succeeded, succeeded.outcome);
    try std.testing.expectEqual(@as(?u8, 0), succeeded.exit_code);
    try std.testing.expectEqualStrings("ok-42", succeeded.stdout);
    try expectNoResidualOfflineMounts(io);

    // Failure path: a non-zero guest exit is surfaced as a structured failure
    // that preserves the exit code and the guest's stderr.
    const failed = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "printf boom >&2; exit 7" },
        5 * 1000,
    );
    defer {
        var result = failed;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.failed, failed.outcome);
    try std.testing.expectEqual(@as(?u8, 7), failed.exit_code);
    try std.testing.expectEqualStrings("boom", failed.stderr);
    try expectNoResidualOfflineMounts(io);

    // Identity verification: if the path the init child resolves and binds
    // names a different inode than the inherited root descriptor -- exactly
    // what a rename racing the child's readlink and mount would produce -- the
    // run must fail closed with a `verify-root` setup error before chroot, and
    // must leave no residual mount behind.  The override points the bind at a
    // decoy directory whose inode cannot match the real staging root.
    {
        const decoy_dir = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-decoy" });
        defer allocator.free(decoy_dir);
        const decoy_link = try std.fs.path.joinZ(allocator, &.{ cwd, ".scratch/offline-root-decoy-link" });
        defer allocator.free(decoy_link);
        Io.Dir.cwd().deleteFile(io, decoy_link) catch {};
        try Io.Dir.cwd().createDirPath(io, decoy_dir);
        defer Io.Dir.cwd().deleteTree(io, decoy_dir) catch {};
        try Io.Dir.cwd().symLink(io, decoy_dir, decoy_link, .{});
        defer Io.Dir.cwd().deleteFile(io, decoy_link) catch {};

        var decoy_executor = try Executor.init(allocator, io, .{
            .root = &root,
            .architecture = Architecture.host(),
            .timeout_ms = 5 * 1000,
            .root_bind_path_override = decoy_link.ptr,
        });
        defer decoy_executor.deinit();
        const rejected = try decoy_executor.runIsolated(
            &.{ "/bin/sh", "-c", "printf escaped > /decoy-marker" },
            5 * 1000,
        );
        defer {
            var result = rejected;
            result.deinit(allocator);
        }
        try std.testing.expectEqual(CommandOutcome.failed, rejected.outcome);
        try std.testing.expectEqual(@as(?u8, namespace_setup_failure_exit), rejected.exit_code);
        try std.testing.expect(std.mem.indexOf(u8, rejected.stderr, "verify-root") != null);
        try expectNoResidualOfflineMounts(io);
    }

    const timed = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "(sleep 10; printf alive > /descendant-marker) & sleep 10" },
        1 * 1000,
    );
    defer {
        var result = timed;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, timed.outcome);
    try Io.sleep(io, .fromSeconds(2), .real);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, marker, .{ .follow_symlinks = false }));
    try expectNoResidualOfflineMounts(io);
    for (0..2) |_| {
        const repeated = try executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        defer {
            var result = repeated;
            result.deinit(allocator);
        }
        try std.testing.expectEqual(CommandOutcome.succeeded, repeated.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    const fds_before_fallbacks = try countOpenFds(io);
    for ([_]PidfdMode{ .force_unavailable, .force_blocked, .force_fd_exhaustion }) |mode| {
        var fallback_executor = try Executor.init(allocator, io, .{
            .root = &root,
            .architecture = Architecture.host(),
            .pidfd_mode = mode,
        });
        const completed = try fallback_executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        fallback_executor.deinit();
        var completed_result = completed;
        defer completed_result.deinit(allocator);
        try std.testing.expectEqual(CommandOutcome.succeeded, completed.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    for ([_]PidfdOpenFn{
        fakePidfdEnosys,
        fakePidfdInval,
        fakePidfdPerm,
        fakePidfdMfile,
        fakePidfdNfile,
    }) |open_fn| {
        var injected_executor = try Executor.init(allocator, io, .{
            .root = &root,
            .architecture = Architecture.host(),
            .pidfd_open_fn = open_fn,
        });
        const completed = try injected_executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        injected_executor.deinit();
        var completed_result = completed;
        defer completed_result.deinit(allocator);
        try std.testing.expectEqual(CommandOutcome.succeeded, completed.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    var injected_unexpected_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_open_fn = fakePidfdUnexpected,
    });
    try std.testing.expectError(
        error.PidfdSetupFailed,
        injected_unexpected_executor.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, 5 * 1000),
    );
    injected_unexpected_executor.deinit();
    try expectNoResidualOfflineMounts(io);
    var unexpected_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_mode = .force_unexpected,
    });
    try std.testing.expectError(
        error.PidfdSetupFailed,
        unexpected_executor.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, 5 * 1000),
    );
    unexpected_executor.deinit();
    try expectNoResidualOfflineMounts(io);
    try std.testing.expectEqual(fds_before_fallbacks, try countOpenFds(io));
    var stalled_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
        .pre_chroot_delay_ms = 3 * 1000,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer stalled_executor.deinit();
    const stalled = try stalled_executor.runIsolated(
        &.{ "/bin/sh", "-c", "exit 0" },
        5 * 1000,
    );
    defer {
        var result = stalled;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, stalled.outcome);
    try expectNoResidualOfflineMounts(io);
    var chatty_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer chatty_executor.deinit();
    const chatty = try chatty_executor.runIsolated(
        &.{ "/bin/sh", "-c", "while true; do printf x; sleep 0.1; done" },
        5 * 1000,
    );
    defer {
        var result = chatty;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, chatty.outcome);
    try expectNoResidualOfflineMounts(io);
    var quiet_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_mode = .force_unavailable,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer quiet_executor.deinit();
    const quiet = try quiet_executor.runIsolated(
        &.{ "/bin/sh", "-c", "exec 1>&- 2>&-; sleep 10" },
        5 * 1000,
    );
    defer {
        var result = quiet;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, quiet.outcome);
    try expectNoResidualOfflineMounts(io);
    Io.Dir.cwd().access(io, fixture, .{ .read = true, .execute = true }) catch
        return error.OfflineRootTeardownIncomplete;
}
