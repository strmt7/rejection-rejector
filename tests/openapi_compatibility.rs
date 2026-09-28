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
