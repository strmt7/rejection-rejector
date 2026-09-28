use std::{env, process::Command};

const UNVERIFIED_COMMIT: &str = "unverified-local-build";

fn reject_controls(name: &str, value: &str, max_len: usize) {
    assert!(
        !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control),
        "{name} contains invalid build metadata"
    );
}

fn main() {
    println!("cargo:rerun-if-env-changed=RR_BUILD_COMMIT");

    let commit = env::var("RR_BUILD_COMMIT").unwrap_or_else(|_| UNVERIFIED_COMMIT.into());
    if commit != UNVERIFIED_COMMIT {
        assert!(
            commit.len() == 40
                && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
                && commit.bytes().all(|byte| !byte.is_ascii_uppercase()),
            "RR_BUILD_COMMIT must be a lowercase 40-character Git SHA"
        );
    }
    reject_controls("RR_BUILD_COMMIT", &commit, 64);

    let target = env::var("TARGET").expect("Cargo must provide TARGET to build scripts");
    let profile = env::var("PROFILE").expect("Cargo must provide PROFILE to build scripts");
    reject_controls("TARGET", &target, 128);
    reject_controls("PROFILE", &profile, 64);

    let rustc = env::var("RUSTC").expect("Cargo must provide RUSTC to build scripts");
    let output = Command::new(&rustc)
        .arg("--version")
        .output()
        .expect("failed to query rustc version");
    assert!(output.status.success(), "rustc --version failed");
    let rustc_version = String::from_utf8(output.stdout)
        .expect("rustc --version returned non-UTF-8 output")
        .trim()
        .to_owned();
    reject_controls("rustc version", &rustc_version, 256);

    println!("cargo:rustc-env=RR_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=RR_BUILD_TARGET={target}");
    println!("cargo:rustc-env=RR_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=RR_BUILD_RUSTC_VERSION={rustc_version}");
}
