# Spack package for ARGUS.
#
# This recipe lets HPC sites that use Spack (and Lmod) install ARGUS
# without any bare-metal toolchain — Spack materializes Rust, LLVM,
# bpf-linker, and OpenSSL from its own packaging layer, then builds
# argus-agent + argus-ebpf in the Spack sandbox.
#
# Add the repo to Spack:
#
#   spack repo add /path/to/ARGUS/deploy/spack
#   spack install argus
#
# Or, if you only want the build dependencies as modules and prefer to
# run cargo manually, use the environment at deploy/spack/spack.yaml:
#
#   spack env activate -p /path/to/ARGUS/deploy/spack
#   spack install
#   cargo build --release --workspace   # runs against modules now loaded
#
# Note: the eBPF artifact requires nightly Rust + bpf-linker, which Spack
# doesn't natively package. The recipe installs them via rustup inside
# the Spack build prefix so they live next to the stable toolchain
# without polluting the user's $HOME.

from spack.package import *


class Argus(Package):
    """Adaptive RDMA Guard & Utilization Sentinel — eBPF telemetry agent
    that detects InfiniBand link degradation in real time on HPC clusters."""

    homepage = "https://github.com/KevinWeiss1995/ARGUS"
    git      = "https://github.com/KevinWeiss1995/ARGUS.git"
    url      = "https://github.com/KevinWeiss1995/ARGUS/archive/refs/tags/v0.1.0.tar.gz"

    maintainers = ["KevinWeiss1995"]

    license("Apache-2.0")

    version("main",  branch="main")
    version("0.1.0", tag="v0.1.0", preferred=True)

    # --- Variants ---
    variant("selinux", default=True,
            description="Build the optional SELinux policy module subpackage.")
    variant("rpm",     default=False,
            description="Wrap the install in an RPM (requires rpm-build).")

    # --- Build dependencies (Spack-managed; no bare-metal install) ---
    depends_on("rust@1.75:",       type="build")
    depends_on("llvm@15:17 +clang", type="build")
    depends_on("openssl",          type=("build", "link"))
    depends_on("pkg-config",       type="build")
    depends_on("git",              type="build")

    # --- Optional ---
    depends_on("rpm",              type="build", when="+rpm")

    # --- Runtime ---
    depends_on("systemd",          type="run")

    # Nightly Rust + bpf-linker aren't in Spack proper; we materialize
    # them under the build prefix via rustup. This keeps them out of
    # $HOME and removable when the install is uninstalled.
    phases = ["bootstrap", "build", "install"]

    def bootstrap(self, spec, prefix):
        """Install nightly Rust + bpf-linker into the build prefix."""
        rustup_home  = join_path(self.stage.source_path, ".rust")
        cargo_home   = join_path(self.stage.source_path, ".cargo")
        mkdirp(rustup_home)
        mkdirp(cargo_home)

        env = os.environ.copy()
        env["RUSTUP_HOME"] = rustup_home
        env["CARGO_HOME"]  = cargo_home
        env["PATH"]        = "{}:{}".format(join_path(cargo_home, "bin"), env["PATH"])

        # Use spack-installed rust as the default toolchain so we get a
        # known stable version for the agent build; add nightly only for
        # the eBPF crate.
        which("rustup")(
            "toolchain", "install", "nightly-2025-01-15", "--profile", "minimal",
            extra_env=env,
        )
        which("rustup")(
            "component", "add", "rust-src", "--toolchain", "nightly-2025-01-15",
            extra_env=env,
        )
        which("cargo")(
            "install", "--version", "0.9.13", "--locked", "bpf-linker",
            extra_env=env,
        )

    def build(self, spec, prefix):
        cargo_home  = join_path(self.stage.source_path, ".cargo")
        env = os.environ.copy()
        env["RUSTUP_HOME"] = join_path(self.stage.source_path, ".rust")
        env["CARGO_HOME"]  = cargo_home
        env["PATH"]        = "{}:{}".format(join_path(cargo_home, "bin"), env["PATH"])

        # User-space agent (stable toolchain shipped by Spack rust).
        which("cargo")("build", "--release", "--workspace", extra_env=env)

        # eBPF object (nightly + bpf-linker from bootstrap).
        which("cargo")("xtask", "build-ebpf", "--release", extra_env=env)

        # SELinux policy module if requested.
        if "+selinux" in spec:
            with working_dir(join_path(self.stage.source_path, "deploy/selinux")):
                make()

    def install(self, spec, prefix):
        mkdirp(prefix.bin)
        mkdirp(join_path(prefix.lib, "argus"))
        mkdirp(join_path(prefix.etc, "argus"))
        mkdirp(join_path(prefix.share, "argus", "systemd"))

        install(
            join_path(self.stage.source_path, "target/release/argus-agent"),
            join_path(prefix.bin, "argusd"),
        )
        symlink("argusd", join_path(prefix.bin, "argus-tui"))

        install(
            join_path(self.stage.source_path,
                      "argus-ebpf/target/bpfel-unknown-none/release/argus-ebpf"),
            join_path(prefix.lib, "argus", "argus-ebpf"),
        )

        # CLI tools
        for tool in ["argus-status", "argus-discover", "argus-manage-targets",
                     "argus-scheduler", "argus-preflight"]:
            src = join_path(self.stage.source_path, "scripts", tool)
            if os.path.isfile(src):
                install(src, join_path(prefix.bin, tool))
                chmod = which("chmod")
                chmod("0755", join_path(prefix.bin, tool))

        # Config templates (operator copies into /etc/argus or activates
        # via a modulefile env-var)
        install(
            join_path(self.stage.source_path, "deploy/argusd.conf"),
            join_path(prefix.etc, "argus", "argusd.conf"),
        )
        install(
            join_path(self.stage.source_path, "deploy/examples/standalone.toml"),
            join_path(prefix.etc, "argus", "argusd.toml"),
        )

        # Systemd unit + drop-in
        install(
            join_path(self.stage.source_path, "deploy/argusd.service"),
            join_path(prefix.share, "argus", "argusd.service"),
        )
        install(
            join_path(self.stage.source_path, "deploy/systemd/modern-caps.conf"),
            join_path(prefix.share, "argus", "systemd", "modern-caps.conf"),
        )

        # SELinux policy artifacts
        if "+selinux" in spec:
            mkdirp(join_path(prefix.share, "argus", "selinux"))
            for f in ["argus.te", "argus.fc", "argus.if", "argus.pp"]:
                src = join_path(self.stage.source_path, "deploy/selinux", f)
                if os.path.isfile(src):
                    install(src, join_path(prefix.share, "argus", "selinux", f))

        # eBPF hash for integrity verification (matches install.sh behaviour).
        sha = which("sha256sum")
        ebpf_path = join_path(prefix.lib, "argus", "argus-ebpf")
        with open(join_path(prefix.etc, "argus", "ebpf.sha256"), "w") as f:
            f.write(sha(ebpf_path, output=str).split()[0] + "\n")

    @run_after("install")
    def post_install_hint(self):
        tty.msg(
            "ARGUS installed into {0}. To run as a system daemon, copy\n"
            "  {0}/share/argus/argusd.service\n"
            "into /etc/systemd/system/ and run:\n"
            "  sudo systemctl daemon-reload && sudo systemctl enable --now argusd\n"
            "For unprivileged testing, use the mock pipeline:\n"
            "  argusd --mode mock --profile skew --tui".format(self.prefix)
        )
