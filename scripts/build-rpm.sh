#!/usr/bin/env bash
# build-rpm.sh — Produce a Rocky 8 / RHEL 8 RPM for ARGUS.
#
# Usage:
#   ./scripts/build-rpm.sh --apptainer           # build inside Apptainer SIF (HPC default)
#   ./scripts/build-rpm.sh --container podman    # alt: Podman / Docker
#   sudo ./scripts/build-rpm.sh                  # bare-metal build via rpmbuild
#   sudo ./scripts/build-rpm.sh --no-build       # skip cargo, package existing artifacts
#   sudo ./scripts/build-rpm.sh --mock <cfg>     # build inside a clean mock chroot
#   sudo ./scripts/build-rpm.sh --sign           # rpmsign with $RPM_GPG_KEY_ID
#   sudo ./scripts/build-rpm.sh --dry-run        # print the rpmbuild commands
#
# Container modes (--apptainer / --container):
#   The build runs inside a pinned Rocky 8 toolchain image so the build
#   host needs only the container runtime — no Rust/LLVM/bpf-linker
#   installed bare-metal. Apptainer is the HPC default (rootless, no
#   daemon, plays nice with shared filesystems). RPM artifacts land in
#   ./out/.
#
# Designed to be run on a Linux build host (Rocky 8, RHEL 8, Fedora) or
# inside the build container. On macOS it errors out.
#
# Output: a binary RPM at ./out/argus-<ver>-1.<arch>.rpm (container mode)
# or ~/rpmbuild/RPMS/<arch>/argus-<ver>-1.<arch>.rpm (bare-metal mode),
# plus an optional argus-selinux subpackage when selinux-policy-devel is
# available.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$REPO_ROOT/packaging/argus.spec"

NO_BUILD=false
MOCK_CFG=""
SIGN=false
DRY_RUN=false
USE_APPTAINER=false
CONTAINER_RUNTIME=""
APPTAINER_SIF="${ARGUS_BUILD_SIF:-deploy/container/argus-build.sif}"
CONTAINER_IMAGE="${ARGUS_BUILD_IMAGE:-localhost/argus-build:latest}"

info()  { echo -e "\033[1;34m==>\033[0m $*"; }
ok()    { echo -e "\033[1;32m OK\033[0m $*"; }
warn()  { echo -e "\033[1;33mWRN\033[0m $*"; }
die()   { echo -e "\033[1;31mERR\033[0m $*" >&2; exit 1; }

# Pass-through args for the inner build inside a container.
INNER_ARGS=()

# Two-pass: pop our own flags, collect anything else for the inner build.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)  NO_BUILD=true; INNER_ARGS+=("--no-build"); shift ;;
        --mock=*)    MOCK_CFG="${1#--mock=}"; INNER_ARGS+=("$1"); shift ;;
        --mock)      shift; MOCK_CFG="$1"; INNER_ARGS+=("--mock" "$1"); shift ;;
        --sign)      SIGN=true; INNER_ARGS+=("--sign"); shift ;;
        --dry-run)   DRY_RUN=true; INNER_ARGS+=("--dry-run"); shift ;;
        --apptainer) USE_APPTAINER=true; shift ;;
        --container=*)
            CONTAINER_RUNTIME="${1#--container=}"; shift ;;
        --container)
            shift; CONTAINER_RUNTIME="${1:-podman}"; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ─── Container dispatch ─────────────────────────────────────────────────
# When invoked with --apptainer or --container, re-enter the build inside
# the appropriate runtime. The sentinel env var ARGUS_IN_BUILD_CONTAINER
# stops the wrapper from recursing once we're already inside.
if [[ -z "${ARGUS_IN_BUILD_CONTAINER:-}" ]]; then
    if $USE_APPTAINER; then
        command -v apptainer >/dev/null || die "apptainer not found. Install: dnf install -y apptainer (Rocky 8: dnf install -y epel-release apptainer)"

        if [[ ! -f "$REPO_ROOT/$APPTAINER_SIF" ]]; then
            info "SIF image missing — building $APPTAINER_SIF"
            if $DRY_RUN; then
                echo "(dry-run) apptainer build --fakeroot $REPO_ROOT/$APPTAINER_SIF $REPO_ROOT/deploy/container/argus-build.def"
            else
                apptainer build --fakeroot \
                    "$REPO_ROOT/$APPTAINER_SIF" \
                    "$REPO_ROOT/deploy/container/argus-build.def"
            fi
        else
            info "Using existing SIF: $APPTAINER_SIF"
        fi

        mkdir -p "$REPO_ROOT/out"
        info "Running build inside Apptainer (output → ./out/)"
        if $DRY_RUN; then
            echo "(dry-run) apptainer run --bind $REPO_ROOT:/src --bind $REPO_ROOT/out:/out $APPTAINER_SIF ${INNER_ARGS[*]}"
            exit 0
        fi
        apptainer run \
            --bind "$REPO_ROOT:/src" \
            --bind "$REPO_ROOT/out:/out" \
            "$REPO_ROOT/$APPTAINER_SIF" \
            "${INNER_ARGS[@]:-}"
        ok "RPM(s) in $REPO_ROOT/out/:"
        find "$REPO_ROOT/out/" -mindepth 1 -maxdepth 1 -exec ls -la {} +
        exit 0
    fi

    if [[ -n "$CONTAINER_RUNTIME" ]]; then
        command -v "$CONTAINER_RUNTIME" >/dev/null || die "$CONTAINER_RUNTIME not found"

        if ! $CONTAINER_RUNTIME image exists "$CONTAINER_IMAGE" 2>/dev/null && \
           ! $CONTAINER_RUNTIME images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -q "^${CONTAINER_IMAGE}$"; then
            info "Container image missing — building $CONTAINER_IMAGE"
            if $DRY_RUN; then
                echo "(dry-run) $CONTAINER_RUNTIME build -f $REPO_ROOT/deploy/container/Containerfile.build -t $CONTAINER_IMAGE $REPO_ROOT"
            else
                $CONTAINER_RUNTIME build \
                    -f "$REPO_ROOT/deploy/container/Containerfile.build" \
                    -t "$CONTAINER_IMAGE" \
                    "$REPO_ROOT"
            fi
        fi

        mkdir -p "$REPO_ROOT/out"
        info "Running build inside $CONTAINER_RUNTIME (output → ./out/)"
        # :Z is for SELinux relabeling on rootful podman; docker chokes on it.
        z_flag=":Z"
        if [[ "$CONTAINER_RUNTIME" == "docker" ]]; then z_flag=""; fi
        if $DRY_RUN; then
            echo "(dry-run) $CONTAINER_RUNTIME run --rm -v $REPO_ROOT:/src$z_flag -v $REPO_ROOT/out:/out$z_flag $CONTAINER_IMAGE ${INNER_ARGS[*]}"
            exit 0
        fi
        $CONTAINER_RUNTIME run --rm \
            -v "$REPO_ROOT:/src$z_flag" \
            -v "$REPO_ROOT/out:/out$z_flag" \
            "$CONTAINER_IMAGE" "${INNER_ARGS[@]:-}"
        ok "RPM(s) in $REPO_ROOT/out/:"
        find "$REPO_ROOT/out/" -mindepth 1 -maxdepth 1 -exec ls -la {} +
        exit 0
    fi
fi

# Preflight — only sensible on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    die "build-rpm.sh must be run on a Linux build host (saw: $(uname -s)). Cross-builds via mock require a Linux kernel."
fi

# Resolve workspace version from Cargo.toml (workspace.package.version).
# Version resolution. Priority:
#   1. $ARGUS_RPM_VERSION (set explicitly by CI from the git tag, so the
#      RPM filename and metadata match the published release).
#   2. Workspace Cargo.toml — used for local development builds. This
#      stays at 0.1.0 between releases; the env-var override is what
#      bumps it for actual published artifacts.
# Without (1), every CI run produces argus-0.1.0-1.el8.x86_64.rpm
# regardless of which tag triggered it — which is exactly the bug
# that wasted three release cycles before this fix.
VERSION="${ARGUS_RPM_VERSION:-$(awk -F\" '/^version[[:space:]]*=/ && !version_seen { print $2; version_seen=1 }' "$REPO_ROOT/Cargo.toml")}"
if [[ -z "$VERSION" ]]; then
    die "could not parse version from Cargo.toml"
fi

# RPM expects a release number — bump in the spec, not here.
RELEASE=1

info "Building argus-$VERSION-$RELEASE for $(uname -m)"

# --- Sanity checks ---
for tool in rpmbuild tar gzip; do
    command -v "$tool" >/dev/null || die "missing tool: $tool (dnf install rpm-build)"
done

if [[ "$NO_BUILD" == false ]]; then
    for tool in cargo rustc; do
        command -v "$tool" >/dev/null || die "missing tool: $tool — see scripts/install.sh for toolchain setup"
    done

    info "cargo build --release --workspace"
    if $DRY_RUN; then
        echo "(dry-run) cd $REPO_ROOT && cargo build --release --workspace"
    else
        (cd "$REPO_ROOT" && cargo build --release --workspace)
    fi

    info "cargo xtask build-ebpf --release"
    if $DRY_RUN; then
        echo "(dry-run) cd $REPO_ROOT && cargo xtask build-ebpf --release"
    else
        (cd "$REPO_ROOT" && cargo xtask build-ebpf --release)
    fi
fi

# --- Stage RPM source tree ---
BUILD_DIR="${RPM_BUILD_DIR:-$HOME/rpmbuild}"
SOURCES_DIR="$BUILD_DIR/SOURCES"
SPECS_DIR="$BUILD_DIR/SPECS"
mkdir -p "$SOURCES_DIR" "$SPECS_DIR"

TARBALL="$SOURCES_DIR/argus-$VERSION.tar.gz"
STAGE_DIR="$(mktemp -d)"
STAGE_TOP="$STAGE_DIR/argus-$VERSION"

info "Staging source tree to $STAGE_TOP"
mkdir -p "$STAGE_TOP"
cp -a \
    "$REPO_ROOT/Cargo.toml" \
    "$REPO_ROOT/Cargo.lock" \
    "$REPO_ROOT/rust-toolchain.toml" \
    "$REPO_ROOT/argus-agent" \
    "$REPO_ROOT/argus-common" \
    "$REPO_ROOT/argus-ebpf" \
    "$REPO_ROOT/xtask" \
    "$REPO_ROOT/deploy" \
    "$REPO_ROOT/packaging" \
    "$REPO_ROOT/scripts" \
    "$REPO_ROOT/README.md" \
    "$STAGE_TOP/"
[[ -f "$REPO_ROOT/LICENSE" ]] && cp -a "$REPO_ROOT/LICENSE" "$STAGE_TOP/"
[[ -f "$REPO_ROOT/CHANGELOG.md" ]] && cp -a "$REPO_ROOT/CHANGELOG.md" "$STAGE_TOP/"

# Stage pre-built binaries into the source tarball whenever they exist.
# The spec's %build checks for target/release/argus-agent and skips
# cargo when it finds one. Staging unconditionally means rpmbuild never
# needs cargo / rust as RPM-managed BuildRequires — they're satisfied
# by the rustup install in the build container that already ran
# cargo build above.
AGENT_BIN="$REPO_ROOT/target/release/argus-agent"
EBPF_BIN="$REPO_ROOT/argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf"
if [[ -f "$AGENT_BIN" && -f "$EBPF_BIN" ]]; then
    info "Staging pre-built agent + eBPF into source tarball"
    mkdir -p "$STAGE_TOP/target/release"
    cp "$AGENT_BIN" "$STAGE_TOP/target/release/"
    mkdir -p "$STAGE_TOP/argus-ebpf/target/bpfel-unknown-none/release"
    cp "$EBPF_BIN" "$STAGE_TOP/argus-ebpf/target/bpfel-unknown-none/release/"
elif $NO_BUILD; then
    [[ -f "$AGENT_BIN" ]] || die "pre-built argus-agent missing at $AGENT_BIN — drop --no-build or run cargo build --release first"
    [[ -f "$EBPF_BIN" ]] || die "pre-built argus-ebpf missing at $EBPF_BIN — drop --no-build or run cargo xtask build-ebpf --release first"
else
    warn "No pre-built binaries found — rpmbuild's %build will attempt cargo build inside its sandbox (likely to fail without a managed Rust toolchain)"
fi

info "Creating $TARBALL"
if $DRY_RUN; then
    echo "(dry-run) tar -C $STAGE_DIR -czf $TARBALL argus-$VERSION/"
else
    tar -C "$STAGE_DIR" -czf "$TARBALL" "argus-$VERSION/"
    rm -rf "$STAGE_DIR"
fi

cp -a "$SPEC" "$SPECS_DIR/argus.spec"

# --- Build ---
RPMBUILD_CMD=(rpmbuild -bb "$SPECS_DIR/argus.spec" --define "_version $VERSION" --define "_release $RELEASE")

if [[ -n "$MOCK_CFG" ]]; then
    command -v mock >/dev/null || die "mock not installed (dnf install mock)"
    info "Building via mock with $MOCK_CFG"
    if $DRY_RUN; then
        echo "(dry-run) mock -r $MOCK_CFG --buildsrpm --spec $SPECS_DIR/argus.spec --sources $SOURCES_DIR"
        echo "(dry-run) mock -r $MOCK_CFG --rebuild <srpm>"
    else
        mock -r "$MOCK_CFG" --buildsrpm --spec "$SPECS_DIR/argus.spec" --sources "$SOURCES_DIR" \
            --resultdir "$BUILD_DIR/MOCK"
        SRPM=$(find "$BUILD_DIR/MOCK" -maxdepth 1 -name '*.src.rpm' | head -1)
        mock -r "$MOCK_CFG" --rebuild "$SRPM" --resultdir "$BUILD_DIR/MOCK"
    fi
else
    info "rpmbuild ${RPMBUILD_CMD[*]}"
    if $DRY_RUN; then
        echo "(dry-run) ${RPMBUILD_CMD[*]}"
    else
        "${RPMBUILD_CMD[@]}"
    fi
fi

# --- Locate output ---
if $DRY_RUN; then
    ok "dry-run complete"
    exit 0
fi

# Build the list of directories to search — only ones that actually
# exist. find returns exit 1 when any path arg is missing, and combined
# with `set -o pipefail` that propagates out of the $(...) substitution
# and aborts the script even after rpmbuild succeeded. We've watched
# this swallow a successful build in CI; never again.
SEARCH_DIRS=()
[[ -d "$BUILD_DIR/RPMS" ]] && SEARCH_DIRS+=("$BUILD_DIR/RPMS")
[[ -d "$BUILD_DIR/MOCK" ]] && SEARCH_DIRS+=("$BUILD_DIR/MOCK")

if (( ${#SEARCH_DIRS[@]} == 0 )); then
    die "rpmbuild succeeded but no output directories were created — check $BUILD_DIR"
fi

RPM_OUT=$(find "${SEARCH_DIRS[@]}" -name "argus-$VERSION-$RELEASE*.rpm" | head -1)
if [[ -z "$RPM_OUT" || ! -f "$RPM_OUT" ]]; then
    die "no RPM matching argus-$VERSION-$RELEASE*.rpm in ${SEARCH_DIRS[*]} — check rpmbuild output above"
fi

# Also enumerate every RPM produced (main + subpackages) for the summary.
mapfile -t ALL_RPMS < <(find "${SEARCH_DIRS[@]}" -name "argus-*-$VERSION-$RELEASE*.rpm" -o -name "argus-$VERSION-$RELEASE*.rpm" | sort -u)

# --- Sign ---
if $SIGN; then
    if [[ -z "${RPM_GPG_KEY_ID:-}" ]]; then
        die "--sign requires RPM_GPG_KEY_ID env var"
    fi
    info "Signing $RPM_OUT with key $RPM_GPG_KEY_ID"
    rpmsign --define "_gpg_name $RPM_GPG_KEY_ID" --addsign "$RPM_OUT"
fi

# --- Summary ---
ok "Built ${#ALL_RPMS[@]} RPM(s):"
for rpm_file in "${ALL_RPMS[@]}"; do
    echo "  $rpm_file"
done
echo ""
rpm -qpi "$RPM_OUT"
echo ""
echo "Install with:"
echo "  sudo dnf install -y ${ALL_RPMS[*]}"
