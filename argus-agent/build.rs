use std::process::Command;

fn main() {
    let git_dir = std::path::Path::new("../.git");
    if git_dir.exists() {
        println!("cargo:rerun-if-changed=../.git/HEAD");
        println!("cargo:rerun-if-changed=../.git/refs");
    }

    let hash = git_string(&["rev-parse", "--short", "HEAD"])
        .or_else(|| std::env::var("ARGUS_BUILD_HASH").ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ARGUS_BUILD_HASH={hash}");

    let date = git_string(&["log", "-1", "--format=%cd", "--date=short"])
        .or_else(|| std::env::var("ARGUS_BUILD_DATE").ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ARGUS_BUILD_DATE={date}");
}

fn git_string(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
