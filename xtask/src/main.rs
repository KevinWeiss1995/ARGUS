use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs (requires Linux + nightly + bpf-linker)
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    BuildAll {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::BuildAll { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
    }
}

fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .expect("cargo locate-project failed");
    let path = String::from_utf8(output.stdout).expect("invalid utf8");
    PathBuf::from(path.trim())
        .parent()
        .expect("no parent")
        .to_path_buf()
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("argus-ebpf");

    if !ebpf_dir.exists() {
        bail!("argus-ebpf directory not found at {}", ebpf_dir.display());
    }

    println!("Building eBPF programs...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.args(["+nightly", "build", "--target=bpfel-unknown-none", "-Z", "build-std=core"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build eBPF programs")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("argus-ebpf");

    println!("eBPF artifact: {}", artifact.display());
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    println!("Building userspace agent...");

    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args(["build", "--workspace"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build userspace")?;
    if !status.success() {
        bail!("Userspace build failed");
    }

    Ok(())
}
