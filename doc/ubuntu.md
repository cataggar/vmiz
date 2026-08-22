# Ubuntu 26.04 images

vmiz has full, core, and bare-metal Ubuntu 26.04 build flavors:

| Flavor | vmiz architecture | Ubuntu architecture | Candidate | Default virtual size | Boot/provisioning |
| --- | --- | --- | --- | --- | --- |
| full | `x86_64` | `amd64` | `Ubuntu-26.04-x86_64.qcow2` | 5 GiB | systemd, cloud-init, WALinuxAgent |
| full | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.qcow2` | 5 GiB | systemd, cloud-init, WALinuxAgent |
| core | `x86_64` | `amd64` | `Ubuntu-26.04-x86_64.core.qcow2` | 3584 MiB | vmizinit, azagent |
| core | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.core.qcow2` | 3584 MiB | vmizinit, azagent |
| baremetal | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.baremetal.qcow2` | 5 GiB | vmizinit, baked administrator |

Bare metal is `aarch64` only: the kernel it names is published for `arm64`
alone, because the machines it exists for are.

Only the two full images are currently release assets. Core candidates are
built, signed, and accepted by a separate protected validation workflow, but
are retained only as short-lived workflow artifacts. Core publication,
release assets, tags, and catalog aliases are deferred to a follow-up.

## Immutable source and package provenance

`scripts/build_generalized_ubuntu2604.zig` uses Canonical's immutable
`release-20260731` cloud-image publication and
`https://snapshot.ubuntu.com/ubuntu/20260731T000000Z`.

For full, the official server cloud disk is the authoritative filesystem and
installed-package baseline. The embedded `vmiz.package_family` debz backend
adds exact `linux-azure` and `walinuxagent` closures without reconstructing the
root from packages.

For core, the same signed cloud disk is used only as the pinned Gen2 GPT and
EFI-system-partition substrate. The server root is discarded and a fresh root
is assembled from an empty debz baseline with exact package roots, in stable
order: `ubuntu-minimal`, `linux-azure`, `openssh-server`, and `sudo`. The
resolved closure must also contain `openssh-client` and `ca-certificates`, and
must not contain cloud-init, WALinuxAgent, `ubuntu-server`, or
`ubuntu-server-minimal`. This source/package decision is part of core
provenance and is not inferred from mutable archive state.

The package-root round trip is native: the mutable QCOW2 is converted to a
raw staging image, `vmiz.ext4_mountless.FileSystem` reads the selected ext4
partition without mounting it, and the package-safe staging view is imported
back through the same API before the raw image is converted back. This path
has no libguestfs, guestfish, supermin, or libguestfs `virt-*` dependency;
mode-`000` entries are read from ext4 bytes rather than made readable on the
host, while their original metadata remains in the native tree.

The root partition is selected by the validated GPT name
`cloudimg-rootfs` and the ext4 filesystem label, not by a fixed `/dev/sdaN`
slot; Canonical's populated partition slots differ between image revisions.

The following inputs are compiled into the builder:

- Canonical key fingerprint:
  `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`
- Pinned Canonical ASCII public-key SHA-256:
  `e581b39fac6bfc199e921788c3c07ac5406fe88db487c7bdcf1e1d2f78fbcf05`
- `SHA256SUMS` SHA-256:
  `d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36`
- `SHA256SUMS.gpg` SHA-256:
  `2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed`
- amd64 image SHA-256:
  `9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`
- amd64 manifest SHA-256:
  `05129d9e221665e0009b7c3a4e62b30040c6b4bf5368d622ea44141c06921514`
- arm64 image SHA-256:
  `3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba`
- arm64 manifest SHA-256:
  `2889120db0432e8029f8f01622efb40ce964e434ba2c81e98937ad1e2616e4f5`
- embedded debz API commit:
  `beac3f20dd93fd98863af71e8fe621d47db663f6`

The builder first verifies the pinned checksum files with its bounded native
OpenPGP verifier. It embeds Canonical's ASCII-armored public key, pins the
complete armored key and its full v4 fingerprint, and accepts only a
4096-bit RSA/65537 key and an unambiguous v4 binary-document RSA/SHA-512
detached signature with Canonical's issuer fingerprint. It has no keyring,
trust database, keyserver, GnuPG configuration, or GnuPG executable
dependency. It then requires exactly one signed checksum entry for the
selected image and manifest. It separately hashes downloaded or `--source`
image bytes. The manifest must contain the expected architecture and the
systemd, cloud-init, cloud-guest-utils, OpenSSH, sudo, and netplan packages.

Every requested package is a separate debz transaction. Full resolves
`linux-azure` and `walinuxagent` from the Canonical image's installed dpkg
baseline. Core resolves its four package roots from the empty root. Both apply
the same exact lock with strict repository priority and no recommends or
downgrades, and retain the exact lock and `transaction-result.json`. Missing
baseline packages, versions, architectures, or closure members fail the
build. The transaction provenance's `lock_sha256` must equal the lock's
semantic digest. The final sorted dpkg inventory at
`/var/lib/vmiz/ubuntu2604-package-lock.tsv` must match the selected flavor and
architecture with no foreign amd64/arm64 packages. Native inspection records
the selected kernel, initramfs, modules directory, and exact lock digest in
`internal-provenance/ubuntu2604-boot-input-evidence.json`.

## Guest and disk contract

Each output is a standalone, zstd-compressed QCOW2. Full has an exact default
virtual size of 5 GiB. Core is exactly 3584 MiB: the size of the pinned signed
substrate, 30% smaller than full. Its fresh root must retain at least 768 MiB
free after package installation and final injection; the measured free bytes,
minimum, and virtual size are provenance fields and validation gates.

Both flavors retain the Canonical Gen2 GPT layout: the root is `/dev/sda1` and
the EFI system partition is `/dev/sda15`. Firmware directly loads the signed
architecture-specific UKI from both the fallback path
(`EFI/BOOT/BOOTX64.EFI` or `EFI/BOOT/BOOTAA64.EFI`) and the corresponding
`EFI/Linux/` path; shim and GRUB are not required for this boot path.

The UKI combines the installed kernel, its newly generated initramfs, and
matching `/lib/modules/<release>`. Which kernel is the right one is a property
of the flavor -- `linux-azure` for full and core, the NVIDIA BaseOS kernel for
bare metal -- and the builder refuses any other, along with missing modules,
wrong PE architecture, invalid signature, missing final UKI, wrong Ubuntu
release, backing file, or wrong virtual size.

The generalized full guest uses:

- systemd, cloud-init with only the Azure datasource, and WALinuxAgent with
  agent provisioning enabled while resource-disk formatting and swap remain
  disabled;
- cloud-init growpart and root-filesystem resize;
- netplan rendered by systemd-networkd with DHCPv4 and DHCPv6;
- OpenSSH with password and keyboard-interactive authentication disabled;
- key-only administrator provisioning, with no baked login credentials; and
- removed default `ubuntu` user, machine identity, SSH host keys, random seed,
  cloud-init state, WALinuxAgent state, and Azure logs.

First boot regenerates per-instance identity and host keys. Acceptance launches
two instances to prove those identities differ, remain stable across reboot,
and are not inherited from the candidate.

The generalized core guest has no systemd service manager, cloud-init, or
WALinuxAgent state. The builder injects architecture-matched static
`/usr/sbin/vmizinit` and `/usr/sbin/azagent` binaries. The signed UKI selects
`init=/sbin/vmizinit vmizinit.mode=persistent vmizinit.azure=auto`.
`vmizinit` is PID 1: it mounts the required kernel filesystems, initializes
networking, generates a machine ID and SSH host keys when absent, supervises
`sshd -D -e`, restarts it after failure, and launches `azagent`.

`azagent` reads Azure's OVF provisioning media, creates the requested
administrator with key-only SSH and passwordless sudo, persists
`/var/lib/azagent/provisioned`, grows the root, formats the Azure resource disk
as XFS at `/d` without swap, mounts managed data disks without formatting
them, and reports Ready in Azure. Explicitly marked local OVF media instead
runs `azagent --skip-ready` for native-QEMU acceptance. Provisioned identity,
authorized keys, host keys, and the sentinel must persist across reboot;
separate instances must not inherit them from the candidate.

`--proxy <url>` reaches the Canonical cloud image and the Ubuntu archive through an HTTP proxy, for a build host with no direct egress. It is named explicitly rather than read from `http_proxy` or `https_proxy`, so a build's egress path is a stated input like every other one and cannot change because of an ambient variable, and it is rejected before anything is downloaded if it is malformed. A proxy carrying a credential is refused, because the credential would have to travel in an argument or an environment variable to get here; debz refuses those on the same grounds. TLS is unaffected: the proxy is asked to `CONNECT`, the session is negotiated end to end with the origin, and the pinned digests and archive signatures still verify the bytes that origin served. The same value is passed to debz, so package download takes the same path the image download does.

### Bare metal

The bare-metal guest is the core guest on a physical machine, and every
difference follows from one fact: there is no Azure underneath it to be
provisioned by.

Its UKI selects `vmizinit.azure=off` rather than `auto`, so vmizinit does not
spend a boot looking for evidence that is never coming. That decision also
means `azagent` never runs -- and `azagent` is what, on core, creates the
administrator, generates the SSH host keys, and writes
`/var/lib/azagent/provisioned`, the sentinel vmizinit waits for before it
starts `sshd`. Left alone, a bare-metal image would boot correctly and never
become reachable, with nothing on the network to say why.

So the image is built already holding what provisioning would have delivered.
The administrator `g` is created at build time from `--authorized-key`, with a
locked password and passwordless sudo, and the image ships
`/usr/local/sbin/vmizinit-access`: the replacement access provider vmizinit
documents for exactly this case, started without waiting on a sentinel because
it brings its own credential path. It generates the host keys on first boot,
creates `/run/sshd` -- which vmizinit does only on the path it replaces -- and
execs `sshd -D -e`. Networking needs no configuration: vmizinit runs its own
DHCP client on the first non-loopback interface.

`validateNoBakedIdentity` refuses SSH host keys for every flavor, because they
must differ per machine. It refuses authorized keys only where identity
arrives at boot, which is what separates bare metal from the two Azure
flavors. A bare-metal build without a key is refused outright: an image nobody
can log in to is not a successful build.

The initramfs is the highest-risk part of the flavor and is checked as such.
An Azure image's dependency-pruned initramfs carries `hv_netvsc` and `sd_mod`;
a machine whose root is behind NVMe and whose management NIC is a USB-attached
Realtek has neither. The image sets `MODULES=most` and names `nvme`,
`nvme_core`, `xhci_hcd`, `xhci_pci`, `usbnet`, `mii`, and `r8152` explicitly,
and then the builder reads the initramfs it is about to seal into the UKI --
the bytes that will boot, not the configuration that asked for them -- and
fails unless `nvme` and `r8152` are in it. Both halves of a concatenated
initramfs are searched; an image whose compressed half cannot be read fails
closed.

`--raw-output` writes a second copy of the validated image with no container
format, for writing to a disk with `dd`. The QCOW2 remains the artifact every
gate is applied to; the raw copy is made from it afterwards, so the two are
the same guest bytes.

## Local build

Use Zig 0.16.0 or later on a matching native Ubuntu host. Install the same
builder dependencies as the release workflow:

```console
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  file jq python3 systemd-boot-efi
```

`systemd-boot-efi` installs only the architecture-matched systemd-boot EFI
stub (`/usr/lib/systemd/boot/efi/linuxx64.efi.stub` on x86_64,
`linuxaa64.efi.stub` on arm64). The Unified Kernel Image is assembled natively:
vmiz appends the deterministic `.linux`, `.initrd`, `.cmdline`, `.osrel`, and
`.uname` PE/COFF sections onto that stub with architecture-correct headers,
alignment, section flags, and subsystem/entry/image sizing, so the builder no
longer installs or invokes `systemd-ukify`, `binutils`, `python3-pefile`, or a
host `linux-image-generic` kernel — the kernel and initrd are extracted from
the guest image. The stub source path and its SHA-256 are recorded in the
signing provenance sidecar.

The builder inventory is therefore limited to the native UKI stub source
(`systemd-boot-efi`), `python3`, `file`, and `jq`. HTTPS/OpenPGP artifact
verification and XZ/zstd decoding and encoding plus newc cpio archive creation
are native, bounded implementations; no host codec library or `curl`, GnuPG,
`cpio`, `xz`, or `zstd` executable is used. X.509 certificate normalization,
canonical-DER fingerprinting, local-key Authenticode signing, and Secure Boot
signature verification are likewise native, so the builder neither installs nor
invokes `openssl`, `sbsign`, or `sbverify`. Standalone zstd-compressed QCOW2
finalization is native as well; all resize, copy, GPT, filesystem mutation, and
final structural validation before publication run without `qemu-img`.

A complete build runs the bounded guest-tool allowlist in a private mount,
PID, and network namespace, so it must be invoked with `sudo` on Linux. The executor
establishes and tears down the namespace using direct, audited Linux syscalls
(`clone`, `mount`, `mknod`, and `chroot`) rather than `util-linux` command
helpers such as `unshare`, `mount`, `umount`, or `setsid`. It mounts only
`dev`, `proc`, `sys`, and `run`, creates the four required device
nodes plus an isolated `tmp`, and tears the namespace down after every
command. `update-initramfs`, `dpkg-query`, and optional `cloud-init clean` are
the only guest commands; systemd enablement and account removal are native
mountless operations.

Run a source-pin preflight using the compiled native HTTPS and OpenPGP
verifiers with:

```console
zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=x86_64 -Dubuntu2604-flavor=core generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=aarch64 -Dubuntu2604-flavor=core generalized-ubuntu2604 -- --preflight-only
```

Release artifacts are fetched by vmiz's native HTTPS downloader. It accepts
only HTTPS URLs, verifies the system TLS certificate chain using TLS 1.2 or
newer, bounds redirects, retries and response sizes, and atomically publishes
only fully downloaded inputs. Pinned artifact SHA-256 values, the complete
Canonical signing-key armor, and its full fingerprint remain mandatory
verification gates. The bounded request-buffer sizing for signed redirects is
informed by [`ghr`'s MIT-licensed HTTP implementation](https://github.com/cataggar/ghr/blob/main/src/http.zig);
vmiz does not vendor that code.

A complete image build requires signing. For local development, supply exactly
one certificate and private key:

```console
sudo -E zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/x86_64/internal-provenance \
  --output artifacts/x86_64/Ubuntu-26.04-x86_64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

sudo -E zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64/internal-provenance \
  --output artifacts/aarch64/Ubuntu-26.04-aarch64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

Build core explicitly for both architectures; the flavor selects the exact
3584 MiB size, core asset name, static guest binaries, and empty-root package
policy:

```console
sudo -E zig build \
  -Dubuntu2604-arch=x86_64 \
  -Dubuntu2604-flavor=core \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/x86_64-core/internal-provenance \
  --output artifacts/x86_64-core/Ubuntu-26.04-x86_64.core.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

sudo -E zig build \
  -Dubuntu2604-arch=aarch64 \
  -Dubuntu2604-flavor=core \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64-core/internal-provenance \
  --output artifacts/aarch64-core/Ubuntu-26.04-aarch64.core.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

Bare metal is built for `aarch64` only, on an `aarch64` host: the guest tools
run in an offline root, so the build host's architecture must match the
guest's. The key is required, and `--raw-output` is what a disk gets written
from:

```console
sudo -E zig build \
  -Dubuntu2604-arch=aarch64 \
  -Dubuntu2604-flavor=baremetal \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64-baremetal/internal-provenance \
  --output artifacts/aarch64-baremetal/Ubuntu-26.04-aarch64.baremetal.qcow2 \
  --raw-output artifacts/aarch64-baremetal/Ubuntu-26.04-aarch64.baremetal.raw \
  --authorized-key ~/.ssh/id_ed25519.pub \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

For the production external signer, build `vmiz`, configure its Artifact
Signing environment, and replace `--uki-signing-key` with:

```console
zig build install-vmiz
export VMIZ_AZURE_TENANT_ID=<tenant-UUID>
export VMIZ_AZURE_CLIENT_ID=<application-client-UUID>
export VMIZ_ARTIFACT_SIGNING_ENDPOINT=https://<region>.codesigning.azure.net/
export VMIZ_ARTIFACT_SIGNING_ACCOUNT=<account>
export VMIZ_ARTIFACT_SIGNING_PROFILE=<profile>

# Add these arguments to either architecture's command:
--uki-sign-command "$PWD/zig-out/bin/vmiz" \
--uki-sign-command-arg sign
```

The external command must be absolute. Local-key and external-command modes
are mutually exclusive. Private signing material is never copied into the
guest.

Without overrides, outputs are written in the current directory. Full work is
cached under `.scratch/ubuntu2604-x86_64` or
`.scratch/ubuntu2604-aarch64`; core uses the corresponding `-core` suffix. A
provenance directory contains the verified `SHA256SUMS`, signature,
architecture manifest, `ubuntu2604-build-provenance.json`,
`uki-signing-<flavor>-<architecture>.json`, and exact-lock plus transaction
provenance files for every flavor-specific package root.

The build validates the source chain before modification and revalidates the
final QCOW2, GPT partitions, Ubuntu identity, package inventory, UKI locations,
PE architecture, and signature. Both workflows additionally use native
`vmiz check` and `vmiz info` to require zstd compression and no backing file,
bind every provenance sidecar into `candidate.json`, and reject private-key
material. External `qemu-img` remains confined to acceptance-time inspection
and the Azure fixed-VHD conversion boundary.

### Local end-to-end release gate

A protected release build must never be dispatched before the corrected
candidate has been built and validated locally. `scripts/ubuntu2604_local_e2e.sh`
runs the strongest feasible local reproduction: it drives the exact release
builder entrypoint (`zig build generalized-ubuntu2604`) through base-image
acquisition and signature verification, embedded debz customize, native UKI
assembly, UKI signing, and standalone zstd QCOW2 finalization, then validates
the finalized candidate exactly as the release workflow does (`vmiz check` plus
`vmiz info --output=json` asserting `qcow2`, an exact 5 GiB virtual size, no
backing file, and zstd cluster compression).

The only deviation from the protected workflow is the signing identity: instead
of the Azure Trusted Signing command, the gate signs with a safe, public,
test-only self-signed key/cert committed under
`tests/fixtures/ubuntu2604-local-signing/` (certificate DER SHA-256
`74556e6a0b540eb0ed5a49d9e75a003987447699df59f1d68456548c47dc8009`). Those
fixtures are guarded deterministically by `zig build test-generalized-ubuntu2604`
(the test loads them through the native local-key path and verifies a signature
against the enrolled certificate), so a corrupted or mismatched fixture fails
before any multi-gigabyte build.

```console
ZIG=$(command -v zig) SEED_CACHE="$HOME/.cache/zig" \
  scripts/ubuntu2604_local_e2e.sh x86_64
```

The driver isolates its privileged (`sudo`) build in an in-tree
`.zig-global-cache`, writes the candidate and provenance under
`.scratch/local-e2e/<arch>/`, and restores ownership afterward. It prints the
finalized candidate size, SHA-256, and the validated `image-info.json` path.

A full arm64 image build is only reproducible on a host with the aarch64
systemd-boot stub (`/usr/lib/systemd/boot/efi/linuxaa64.efi.stub`); on an
x86_64 host it is not. The arm64 resolve→customize transition that failed in
production is instead covered deterministically and offline by
`zig build test-package-family` (the arm64 exact-lock handoff through the
package-family boundary) and by debz's `production_backend_customize_test.zig`
(the real backend provisioning the absent `var/lib/debz` lock root). Run the
full arm64 gate (`scripts/ubuntu2604_local_e2e.sh aarch64`) only on a matching
aarch64 runner.

## Acceptance infrastructure


Native acceptance is deliberately not emulation. Each architecture requires a
matching Linux runner with readable and writable `/dev/kvm`, QEMU, OVMF or
AAVMF, `swtpm`, `virt-fw-vars`, `sbverify`, and OpenSSH. It enrolls
the exact candidate leaf in UEFI `db` and asserts the standalone GPT image,
Secure Boot, signed UKI, vTPM, lockdown, signed modules, rejection of a
tampered UKI, key-only SSH, cloud-init, WALinuxAgent, netplan/networkd, root
growth, generalized identity, reboot/reconnect, and clean service health.

The `python3-virt-firmware` package and its `virt-fw-vars` executable are
firmware-variable tooling, not libguestfs. They remain required solely to
create per-instance Secure Boot variable stores for QEMU acceptance.
`qemu-utils` remains in native acceptance for candidate inspection and in
Azure acceptance for the documented fixed-VHD conversion boundary.

Azure acceptance requires an Azure subscription and OIDC application allowed
to create and delete the temporary resource group and its managed disks,
Compute Gallery/image definition/version with custom UEFI `db`, network,
public IP, Trusted Launch VM, and managed data disk. The selected region and
VM size must support the candidate architecture, Gen2, Trusted Launch, Secure
Boot, and vTPM. Acceptance converts the exact QCOW2 to a validated fixed VHD,
then asserts the signer, UKI, provisioning, key-only SSH, runtime Ubuntu
identity, agent Ready state, root growth, data disk, reboot, vTPM, lockdown,
and module signatures. Cleanup deletes only the expected resource group with
the exact run ownership tags.

Core acceptance adds the vmizinit PID-1 and SSH-supervision contract, local
OVF `azagent --skip-ready`, Azure Ready reporting, provisioning and identity
persistence, resource-disk formatting, managed-data-disk mount-only behavior,
and explicit absence of cloud-init, WALinuxAgent, and a systemd service
manager.

## Core validation workflow

`.github/workflows/ubuntu2604-core-validation.yml` is a separate manually
dispatched workflow restricted to `main`. It uses the same protected
`ubuntu2604-signing` and `ubuntu2604-release` environments and OIDC subjects
described below, with serialized non-cancelling concurrency. No tag is
required.

The workflow builds and signs exactly `x86_64-core` and `aarch64-core`, then
requires both native-QEMU jobs and both Azure Trusted Launch jobs. Candidate
reuse accepts only a completed manual run of this same workflow at the exact
current remote `main` commit and exact run attempt, with both named build jobs
successful and exactly two nonempty, unexpired candidate artifacts.

Candidates, native results, Azure results, and a final digest-bound
two-architecture validation manifest are uploaded only as workflow artifacts.
The workflow has no publish job, release command, tag contract, release asset,
or catalog mutation. Successful protected validation does not itself publish
core images; all publication work remains explicitly deferred.

## Full/server release workflow

`.github/workflows/ubuntu2604-release.yml` is manually dispatched from
`main` and still publishes exactly the two full/server assets. It does not
accept core keys or assets, and `scripts/ubuntu2604_publish.sh` is intentionally
unchanged. Before dispatch:

1. Create or retarget the required tag `Ubuntu-26.04-20260822` to the exact
   current `main` commit. Lightweight and annotated tags are accepted; force
   push the tag when it already exists, then verify the remote resolves to the
   current `main` commit before dispatch.
2. Configure protected environment `ubuntu2604-signing`, restricted to
   `main` and requiring reviewers, with variables
   `VMIZ_AZURE_TENANT_ID`, `VMIZ_AZURE_CLIENT_ID`,
   `VMIZ_ARTIFACT_SIGNING_ENDPOINT`, `VMIZ_ARTIFACT_SIGNING_ACCOUNT`, and
   `VMIZ_ARTIFACT_SIGNING_PROFILE`.
3. Configure protected environment `ubuntu2604-release` the same way, with
   secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` and variables `AZURE_LOCATION_X64`,
   `AZURE_LOCATION_ARM64`, `AZURE_VM_SIZE_X64`, and
   `AZURE_VM_SIZE_ARM64`.
4. Configure both Entra federated credentials with issuer
   `https://token.actions.githubusercontent.com` and audience
   `api://AzureADTokenExchange`. Their subjects are respectively
   `repo:cataggar/vmiz:environment:ubuntu2604-signing` and
   `repo:cataggar/vmiz:environment:ubuntu2604-release`.

Top-level permissions are `actions: read` and `contents: read`. Signing and
Azure acceptance add only `id-token: write`; native acceptance remains
read-only. Publication uses `actions: read` and `contents: write`.

The prepare gate binds the run to the current remote `main` commit and tag.
An optional `candidate_run_id` may reuse only a completed manual run on
`main` for that same commit and exact run attempt. Both named build jobs must
have succeeded and exactly two non-expired, nonempty candidate artifacts must
match the commit and attempt. Reused candidates still rerun native and Azure
acceptance.

Publication requires two successful build candidates, two digest-bound native
results, and two exact Azure results. It stages only the two QCOW2 files,
creates or resets the release as a draft, uploads with clobber, removes stale
assets, and verifies the remote draft has exactly the two expected names and
sizes. It then downloads both assets and verifies their SHA-256 and size before
making the release non-draft, followed by one final remote exact-two-asset
check. On publication failure the release is retained as a draft; job cleanup
removes local staging, candidates, derived VHDs, credentials, and only
ownership-tagged Azure resources.

## Catalog aliases

`vmiz qemu Ubuntu` and exact Ubuntu catalog aliases are intentionally not
present yet. They may be added only after the real published asset SHA-256
digests and the final signing-certificate fingerprint are known and pinned.
Do not substitute build-time guesses or copy values from another release.
Until then, boot an explicitly supplied image path and provide its independent
Secure Boot trust material as described in [QEMU](qemu.md).
