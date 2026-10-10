//! Persistence round-trip contract for evaluation reports.
//!
//! serde_json's default float parser is 1-ULP imprecise, which made stored
//! reports compare unequal to in-memory values under exact equality. The
//! `float_roundtrip` feature makes parsing correctly rounded; this test pins
//! that contract so the feature cannot be dropped silently.

/// Floats written to a report and parsed back must be bit-identical.
#[test]
fn report_floats_round_trip_bit_exactly() {
    for value in [
        0.909_090_909_090_909_2_f64,
        0.1_f64,
        1.0 / 3.0,
        f64::from_bits(0x3ff0000000000001),
        0.051_424_874_864_956_91,
    ] {
        let serialized = serde_json::to_string(&value).expect("serialize");
        let parsed: f64 = serde_json::from_str(&serialized).expect("parse");
        assert_eq!(
            parsed.to_bits(),
            value.to_bits(),
            "round-trip changed the float: {value:?} via {serialized}"
        );
    }
}

/// The 1-ULP defect case that motivated the feature: the classic
/// 0.9090909090909091 parse must land on the exact same double.
#[test]
fn the_known_ulp_regression_case_stays_exact() {
    let text = "0.9090909090909091";
    let parsed: f64 = serde_json::from_str(text).expect("parse");
    assert_eq!(parsed, 0.909_090_909_090_909_1_f64);
}
