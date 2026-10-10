//! CLI contract tests for the `rr` fleet interface.
//!
//! These pin the machine-readable surface that deployment tooling consumes:
//! `build-info`, `contract-info` and `policy-schema` must emit valid JSON
//! with stable keys and exit 0, and invalid invocations must fail loudly
//! with a non-zero exit code instead of silently succeeding.

use std::process::Command;

/// Run the `rr` binary with the given arguments.
///
/// Inputs: `args` — command-line arguments. Output: the `Output` of the
/// spawned process (status, stdout, stderr).
fn rr(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rr"))
        .args(args)
        .output()
        .expect("run rr")
}

/// Parse stdout as a JSON object for contract assertions.
///
/// Inputs: `output` — process output. Output: the parsed object; panics when
/// the command did not exit cleanly or did not emit a JSON object.
fn json_stdout(output: &std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must be JSON")
}

/// `build-info` is the fleet identity: valid JSON with a schema version and
/// the application version, so rollout tooling can gate on it.
#[test]
fn build_info_emits_machine_readable_identity() {
    let value = json_stdout(&rr(&["build-info"]));
    assert!(
        value.get("schema_version").is_some(),
        "schema_version required"
    );
    assert!(
        value.get("application_version").is_some(),
        "application_version required"
    );
}

/// `contract-info` carries the exact API fingerprint: deployment drift checks
/// compare this SHA-256, so it must be present and well-formed.
#[test]
fn contract_info_exposes_a_well_formed_api_fingerprint() {
    let value = json_stdout(&rr(&["contract-info"]));
    let fingerprint = value
        .get("api_contract_sha256")
        .and_then(|v| v.as_str())
        .expect("api_contract_sha256 required");
    assert_eq!(fingerprint.len(), 64, "fingerprint must be a hex SHA-256");
    assert!(
        fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be hexadecimal"
    );
}

/// `policy-schema` is a deployment artifact: it must be a valid JSON document
/// declaring the schema dialect so enterprise rollout can validate policies.
#[test]
fn policy_schema_is_a_valid_json_schema_document() {
    let value = json_stdout(&rr(&["policy-schema"]));
    assert!(
        value.get("$schema").is_some(),
        "policy schema must declare $schema"
    );
    assert!(
        value.get("properties").is_some(),
        "policy schema must declare properties"
    );
}

/// Invalid invocations must fail loudly: automation relies on exit codes, so
/// an unknown subcommand must not exit 0.
#[test]
fn unknown_subcommand_fails_with_nonzero_exit() {
    let output = rr(&["definitely-not-a-command"]);
    assert!(
        !output.status.success(),
        "unknown subcommand must exit non-zero"
    );
    assert!(
        !output.stderr.is_empty(),
        "failure must be explained on stderr"
    );
}
