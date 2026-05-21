#!/usr/bin/env bash
# build-rpm.sh — Produce a Rocky 8 / RHEL 8 RPM for ARGUS.
#
# Usage:
#   sudo ./scripts/build-rpm.sh                  # full build via rpmbuild
#   sudo ./scripts/build-rpm.sh --no-build       # skip cargo, package existing artifacts
#   sudo ./scripts/build-rpm.sh --mock <cfg>     # build inside a clean mock chroot
#   sudo ./scripts/build-rpm.sh --sign           # rpmsign with $RPM_GPG_KEY_ID
#   sudo ./scripts/build-rpm.sh --dry-run        # print the rpmbuild commands
#
# Designed to be run on a Linux build host (Rocky 8, RHEL 8, Fedora). On macOS
# it will print an error before doing anything destructive.
#
# Output: a single binary RPM under ~/rpmbuild/RPMS/<arch>/argus-<ver>-1.<arch>.rpm,
# plus an optional SELinux-policy subpackage when selinux-policy-devel is present.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$REPO_ROOT/packaging/argus.spec"

NO_BUILD=false
MOCK_CFG=""
SIGN=false
DRY_RUN=false

info()  { echo -e "\033[1;34m==>\033[0m $*"; }
ok()    { echo -e "\033[1;32m OK\033[0m $*"; }
warn()  { echo -e "\033[1;33mWRN\033[0m $*"; }
die()   { echo -e "\033[1;31mERR\033[0m $*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --mock=*)   MOCK_CFG="${arg#--mock=}" ;;
        --mock)     shift; MOCK_CFG="$1" ;;
        --sign)     SIGN=true ;;
        --dry-run)  DRY_RUN=true ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0
            ;;
        *) die "Unknown option: $arg" ;;
    esac
done

# Preflight — only sensible on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    die "build-rpm.sh must be run on a Linux build host (saw: $(uname -s)). Cross-builds via mock require a Linux kernel."
fi

# Resolve workspace version from Cargo.toml (workspace.package.version).
VERSION=$(awk -F\" '/^version[[:space:]]*=/ && !version_seen { print $2; version_seen=1 }' "$REPO_ROOT/Cargo.toml")
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

# Stage pre-built binaries when --no-build was passed
if $NO_BUILD; then
    info "Bundling pre-built binaries (--no-build)"
    if [[ ! -f "$REPO_ROOT/target/release/argus-agent" ]]; then
        die "pre-built argus-agent missing; drop --no-build or run cargo build --release first"
    fi
    if [[ ! -f "$REPO_ROOT/argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf" ]]; then
        die "pre-built argus-ebpf missing; drop --no-build or run cargo xtask build-ebpf --release first"
    fi
    mkdir -p "$STAGE_TOP/target/release"
    cp "$REPO_ROOT/target/release/argus-agent" "$STAGE_TOP/target/release/"
    mkdir -p "$STAGE_TOP/argus-ebpf/target/bpfel-unknown-none/release"
    cp "$REPO_ROOT/argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf" \
        "$STAGE_TOP/argus-ebpf/target/bpfel-unknown-none/release/"
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

RPM_OUT=$(find "$BUILD_DIR/RPMS" "$BUILD_DIR/MOCK" -name "argus-$VERSION-$RELEASE*.rpm" 2>/dev/null | head -1)
if [[ -z "$RPM_OUT" || ! -f "$RPM_OUT" ]]; then
    die "no RPM produced — check rpmbuild output above"
fi

# --- Sign ---
if $SIGN; then
    if [[ -z "${RPM_GPG_KEY_ID:-}" ]]; then
        die "--sign requires RPM_GPG_KEY_ID env var"
    fi
    info "Signing $RPM_OUT with key $RPM_GPG_KEY_ID"
    rpmsign --define "_gpg_name $RPM_GPG_KEY_ID" --addsign "$RPM_OUT"
fi

# --- Summary ---
ok "Built $RPM_OUT"
echo ""
rpm -qpi "$RPM_OUT"
echo ""
echo "Install with:"
echo "  sudo dnf install -y $RPM_OUT"
