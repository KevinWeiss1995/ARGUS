# Building ARGUS on HPC clusters without polluting the system

> **TL;DR for most sites:** you don't need to build at all. Every tagged
> release publishes a signed RPM as a GitHub release artifact. See the
> "Use the published RPM" section near the bottom — that's the fastest
> path for sites where `apptainer build --fakeroot` is disabled and the
> admin doesn't want to install a build toolchain.

HPC environments typically resist `curl | sh` rustup installs and bare-metal
`dnf install -y rust cargo clang llvm` because those leak into a shared
build host's global state. This document covers three professional, fully
dependency-managed paths that keep the build toolchain isolated — for
sites that want to rebuild from source.

| Method                | Build host needs                          | Where build deps live          | When to use                                                                 |
| --------------------- | ----------------------------------------- | ------------------------------ | --------------------------------------------------------------------------- |
| **Apptainer** (default) | `apptainer` (already on most HPC sites)  | Inside `argus-build.sif`        | First choice. Rootless, single-file image, plays nicely with shared FS.     |
| **Spack**             | `spack` (already on many academic sites) | Spack install prefix + modules  | Site is already Spack-managed and uses Lmod for everything else.            |
| **Podman / Docker**   | `podman` (stock Rocky 8) or `docker`     | Inside `argus-build:latest`     | Site has container runtime but not Apptainer.                                |

The runtime install path is unchanged regardless of build method — the output
is an RPM that you deploy via `dnf install` or the Ansible playbook.

---

## Method 1 — Apptainer (recommended)

### One-time: build the SIF image

The SIF (Singularity Image Format) file is a single relocatable artifact
containing Rocky 8 + the pinned ARGUS toolchain. Build it once on any
host with Apptainer and `--fakeroot` available (most HPC clusters
enable user namespaces by default):

```bash
git clone https://github.com/KevinWeiss1995/ARGUS.git
cd ARGUS
apptainer build --fakeroot \
    deploy/container/argus-build.sif \
    deploy/container/argus-build.def
```

If your site disables `--fakeroot`, ask an admin to do the one-time build
as root and copy the SIF to a shared location:

```bash
# As root, anywhere with apptainer:
sudo apptainer build argus-build.sif argus-build.def
sudo cp argus-build.sif /opt/argus/argus-build.sif
chmod 0644 /opt/argus/argus-build.sif
```

The SIF is portable — copy it to any node that has Apptainer.

### Each build: run the SIF

```bash
mkdir -p out
apptainer run \
    --bind $PWD:/src \
    --bind $PWD/out:/out \
    deploy/container/argus-build.sif

# Or via the wrapper:
./scripts/build-rpm.sh --apptainer
```

The wrapper will build the SIF automatically if it doesn't exist yet.

Output lands in `./out/argus-0.1.0-1.<arch>.rpm` (plus
`argus-selinux-0.1.0-1.noarch.rpm` when `selinux-policy-devel` is in
the SIF).

### To upgrade the toolchain

Edit the `%arguments` block in `deploy/container/argus-build.def` to bump
`RUST_VERSION` / `RUST_NIGHTLY` / `BPF_LINKER_VERSION`, then rebuild the
SIF. Existing SIFs continue to work — multiple toolchain versions can
coexist as separate files.

### Cleanup

The SIF is just a file. Delete it when you're done:

```bash
rm deploy/container/argus-build.sif
```

Nothing was installed bare-metal at any point.

---

## Method 2 — Spack

Sites that already use Spack get the same benefits via Spack's normal
mechanisms — Rust, LLVM, OpenSSL all materialize as modules.

### Full install (Spack manages everything, including ARGUS itself)

```bash
# Add the ARGUS recipe to your Spack repos
spack repo add /path/to/ARGUS/deploy/spack

# Install (concretization picks compatible versions automatically)
spack install argus

# Make it available
spack load argus

# Smoke test
argusd --mode mock --tui
```

To produce an RPM as well:

```bash
spack install argus +rpm
```

Sites that want a specific Rust version can pin it:

```bash
spack install argus ^rust@1.83.0
```

### Build-deps only (you run cargo manually)

If you'd rather Spack just provide Rust/LLVM as Lmod modules and you'll
build with cargo directly (faster incremental builds during development):

```bash
spack env activate -p /path/to/ARGUS/deploy/spack
spack install
spack env loads -r > load.sh
source load.sh

# Now rust, llvm, openssl etc. are in your environment as modules.
cd /path/to/ARGUS
cargo build --release --workspace
```

To install nightly + bpf-linker into the user's `~/.cargo` while still
keeping the rest under Spack:

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo xtask build-ebpf --release
```

(Or skip the nightly altogether and use `--no-ebpf` mock mode for
unprivileged testing.)

### Cleanup

```bash
spack uninstall argus
spack env deactivate
```

Spack tracks every file it installed — removal is exhaustive.

---

## Method 3 — Podman / Docker

For sites without Apptainer but with a container runtime:

```bash
./scripts/build-rpm.sh --container podman
# or
./scripts/build-rpm.sh --container docker
```

The wrapper builds `localhost/argus-build:latest` from
`deploy/container/Containerfile.build` on first run and reuses the image
afterwards. RPM output lands in `./out/`.

Differences from Apptainer:
- Podman needs `:Z` mount labels for SELinux Enforcing hosts (handled
  by the wrapper).
- Docker requires root (or docker group membership); Podman is rootless.
- The image is in the runtime's local registry, not a portable file.

---

## "I just want to test it on a login node, no admin"

You don't need any of the above for that. The mock pipeline runs
unprivileged on any Linux/macOS host with a Rust toolchain:

```bash
# Stable Rust is enough for the agent (eBPF nightly is not needed for
# mock/replay). If your site provides a rust module:
module load rust   # or whatever your site calls it

cargo run --release -- --mode mock --profile skew --tui
```

If no Rust module is available, run the build from the Apptainer SIF
without producing an RPM:

```bash
apptainer exec --bind $PWD:/src deploy/container/argus-build.sif \
    bash -c 'cd /src && cargo build --release --workspace'
./target/release/argus-agent --mode mock --tui
```

This validates that the binary works on the cluster's kernel/glibc/IB
stack before you commit to a full RPM install via Ansible.

---

## Use the published RPM (no build at all)

For sites where `apptainer build --fakeroot` is disabled and no admin
wants to add toolchain packages to a build host, skip the build entirely
and use the RPM that ARGUS CI publishes on every release tag.

```bash
TAG=v0.1.0
ARCH=x86_64
URL=https://github.com/KevinWeiss1995/ARGUS/releases/download/$TAG

# Download + verify
wget $URL/argus-${TAG#v}-1.el8.$ARCH.rpm
wget $URL/argus-${TAG#v}-1.el8.$ARCH.rpm.sha256
sha256sum -c argus-${TAG#v}-1.el8.$ARCH.rpm.sha256

# Install (single host)
sudo dnf install -y ./argus-${TAG#v}-1.el8.$ARCH.rpm

# Optional SELinux subpackage if your nodes run Enforcing
wget $URL/argus-selinux-${TAG#v}-1.el8.noarch.rpm
sudo dnf install -y ./argus-selinux-${TAG#v}-1.el8.noarch.rpm

# Validate, then enable
sudo argus-preflight
sudo systemctl enable --now argusd
curl -s localhost:9100/health
```

The published RPM is built by `.github/workflows/release.yml` in the
same Rocky 8 toolchain container that local builds use, so the binary
is bit-identical to what you'd produce with `./scripts/build-rpm.sh --apptainer`
on a host where you DO have fakeroot. Both methods produce SHA-256
attestations.

Browse releases: <https://github.com/KevinWeiss1995/ARGUS/releases>

## Runtime install (any build path)

Regardless of whether you used a published RPM or rebuilt locally,
install the same way:

```bash
sudo dnf install -y ./argus-*.rpm
sudo argus-preflight
sudo systemctl enable --now argusd
```

Or fleet-deploy via Ansible — see [`deploy/ansible/README.md`](../deploy/ansible/README.md).

The RPM declares its runtime requirements (`systemd`, `chrony`) and is
tracked by `rpm -qa`. Nothing additional ends up on the host outside
package management.
