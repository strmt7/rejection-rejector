use serde_json::Value;
use std::collections::BTreeSet;

const BASELINE: &str = include_str!("../docs/openapi-v1-baseline.json");
const CURRENT: &str = include_str!("../docs/openapi-v1.json");

fn ignored(path: &str, key: &str) -> bool {
    matches!(
        key,
        "description" | "summary" | "title" | "examples" | "example"
    ) || (path == "$.info" && key == "version")
}

fn set(values: &[Value]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| serde_json::to_string(value).expect("JSON value is serializable"))
        .collect()
}

fn assert_additive(base: &Value, current: &Value, path: &str) {
    match (base, current) {
        (Value::Object(base), Value::Object(current)) => {
            for (key, base_value) in base {
                if ignored(path, key) {
                    continue;
                }
                let current_value = current.get(key).unwrap_or_else(|| {
                    panic!("OpenAPI v1 compatibility break: removed {path}.{key}")
                });
                let child = format!("{path}.{key}");
                if matches!(key.as_str(), "required" | "enum") {
                    let base_values = base_value
                        .as_array()
                        .unwrap_or_else(|| panic!("{child} baseline must be an array"));
                    let current_values = current_value
                        .as_array()
                        .unwrap_or_else(|| panic!("{child} current value must be an array"));
                    let missing: Vec<_> = set(base_values)
                        .difference(&set(current_values))
                        .cloned()
                        .collect();
                    assert!(
                        missing.is_empty(),
                        "OpenAPI v1 compatibility break at {child}: removed values {missing:?}"
                    );
                } else {
                    assert_additive(base_value, current_value, &child);
                }
            }
        }
        (Value::Array(base), Value::Array(current)) => {
            assert_eq!(
                base, current,
                "OpenAPI v1 compatibility break at {path}: structural array changed"
            );
        }
        _ => {
            assert_eq!(
                base, current,
                "OpenAPI v1 compatibility break at {path}: value/type changed"
            );
        }
    }
}

#[test]
fn current_openapi_is_additive_over_the_frozen_v1_baseline() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let current: Value = serde_json::from_str(CURRENT).unwrap();
    assert_eq!(baseline["openapi"], "3.1.0");
    assert_eq!(current["openapi"], "3.1.0");
    assert_additive(&baseline, &current, "$");
}

#[test]
fn compatibility_baseline_is_intentionally_older_than_current_contract() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let current: Value = serde_json::from_str(CURRENT).unwrap();
    assert_eq!(baseline["info"]["version"], "1.10.0");
    assert_ne!(baseline["info"]["version"], current["info"]["version"]);
    assert!(
        current["paths"]
            .as_object()
            .unwrap()
            .contains_key("/v1/metrics/openmetrics")
    );
    assert!(
        !baseline["paths"]
            .as_object()
            .unwrap()
            .contains_key("/v1/metrics/openmetrics")
    );
}

// why: the web interface contract additions must stay additive over the
// frozen v1 baseline — the read API keeps every byte of its shape while the
// page, the settings view and the write-command channel appear only as new
// paths; a removal or reshaping of an existing route would break the
// compatibility promise this test exists to pin.
#[test]
fn web_page_and_write_command_routes_are_additive_contract_extensions() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let current: Value = serde_json::from_str(CURRENT).unwrap();
    let paths = current["paths"].as_object().unwrap();
    for route in [
        "/",
        "/v1/settings",
        "/v1/commands/edit-draft",
        "/v1/commands/regenerate",
        "/v1/commands/dismiss",
        "/v1/commands/send",
        "/v1/commands/update-settings",
        "/v1/commands/automatic-arm",
    ] {
        assert!(paths.contains_key(route), "OpenAPI missing {route}");
        assert!(
            !baseline["paths"].as_object().unwrap().contains_key(route),
            "frozen baseline must not gain {route}"
        );
    }
    for route in ["/v1/commands/send", "/v1/commands/automatic-arm"] {
        let post = &paths[route]["post"];
        assert!(post["requestBody"]["content"]["application/json"]["schema"]["$ref"].is_string());
        assert!(post["responses"]["409"]["$ref"].is_string());
    }
    // Stable typed contract pieces the write channel depends on.
    assert!(current["components"]["schemas"]["OperationStatus"].is_object());
    assert!(current["components"]["schemas"]["WriteResponse"].is_object());
    assert!(current["components"]["schemas"]["SettingsView"].is_object());
    assert!(current["components"]["responses"]["WriteConflict"].is_object());
    assert!(current["components"]["responses"]["RequestTooLarge"].is_object());
    // The strict CSP is contractual and present on every documented response.
    for response in current["components"]["responses"]
        .as_object()
        .unwrap()
        .values()
    {
        assert!(response["headers"]["Content-Security-Policy"]["$ref"].is_string());
    }
}
