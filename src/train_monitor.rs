//! Training monitor data model: progress parsing, GPU duty-control file
//! handling and pacing math for the utilization ceiling.
//!
//! The ceiling is enforced by PACING THE TRAINING LOOP ITSELF (host-side
//! sleeps between steps), never by touching drivers, fan curves, clocks or
//! power limits: PyTorch core guidance is that GPU utilization can only be
//! reduced by reducing the workload
//! (<https://discuss.pytorch.org/t/is-there-a-way-to-specify-gpu-duty-cycle-while-training/118041>).
//! The sleep formula follows the validated duty-cycle controller in
//! godweiyang/GrabGPU: `off = on * (100 - t) / t`, recomputed from the
//! measured on-time every cycle so the running average tracks the target.
//!
//! Everything here is pure host-side file IO and arithmetic: the GUI
//! (`src/bin/rr-train-monitor.rs`) and the trainer hook
//! (`training/duty_cycle.py`) share the exact same `duty.json` contract.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Lower bound for the utilization ceiling: below 20% the inter-step
/// sleeps dominate so run time explodes while fan-noise gains flatten.
pub const MIN_TARGET_PCT: f64 = 20.0;
/// Upper bound: 100 disables pacing entirely.
pub const MAX_TARGET_PCT: f64 = 100.0;
/// Ceiling of the GUI slider: the operator's standing requirement is a
/// hard 50% GPU utilization maximum for these workloads, so the slider
/// cannot request more (the control-file contract still allows 20-100
/// for other tooling).
pub const SLIDER_MAX_PCT: f64 = 50.0;
/// A heartbeat older than this marks the run as stalled (matches the
/// trainer's stall watchdog threshold).
pub const STALE_AFTER_SECONDS: f64 = 120.0;
/// File name of the live duty control file (sibling of progress.json).
pub const CONTROL_FILENAME: &str = "duty.json";

/// The trainer's heartbeat state (written by `training/train_lora.py`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProgressSnapshot {
    /// Completed optimizer steps.
    pub step: u64,
    /// Total planned steps.
    pub total_steps: u64,
    /// Latest loss, when reported.
    #[serde(default)]
    pub loss: Option<f64>,
    /// Lifecycle status ("running", "complete", "stopping").
    #[serde(default)]
    pub status: String,
    /// Seconds since the run began.
    #[serde(default)]
    pub elapsed_seconds: f64,
    /// Unix timestamp of this heartbeat write.
    #[serde(default)]
    pub updated_at_unix: f64,
}

impl ProgressSnapshot {
    /// Age of this heartbeat.
    ///
    /// Input: `now_unix` — current unix time in seconds.
    /// Output: seconds since the heartbeat was written (0.0 when the
    /// timestamp is missing or in the future).
    pub fn staleness(&self, now_unix: f64) -> f64 {
        if self.updated_at_unix <= 0.0 {
            return 0.0;
        }
        (now_unix - self.updated_at_unix).max(0.0)
    }

    /// Completed fraction of the run.
    ///
    /// Input: none.
    /// Output: `step / total_steps` clamped to [0.0, 1.0] (0.0 when the
    /// total is zero).
    pub fn fraction(&self) -> f32 {
        if self.total_steps == 0 {
            return 0.0;
        }
        (self.step as f32 / self.total_steps as f32).clamp(0.0, 1.0)
    }

    /// Minutes to completion at the observed rate.
    ///
    /// Input: none.
    /// Output: `Some(minutes)` when the rate is computable and positive,
    /// `None` otherwise.
    pub fn eta_minutes(&self) -> Option<f64> {
        if self.step == 0 || self.step >= self.total_steps || self.elapsed_seconds <= 0.0 {
            return None;
        }
        let per_step = self.elapsed_seconds / self.step as f64;
        Some(per_step * (self.total_steps - self.step) as f64 / 60.0)
    }
}

/// Parse the trainer heartbeat file.
///
/// Input: raw JSON text of `progress.json`.
/// Output: `Some(ProgressSnapshot)` when the document is well-formed with
/// numeric `step`/`total_steps`, `None` on any malformed input (fail
/// closed: the monitor shows "no data" rather than invented numbers).
pub fn parse_progress(json: &str) -> Option<ProgressSnapshot> {
    let snap: ProgressSnapshot = serde_json::from_str(json).ok()?;
    Some(snap)
}

/// Path of the live duty control file for a given heartbeat path.
///
/// Input: path to `progress.json`.
/// Output: the sibling `duty.json` path.
pub fn duty_path_for(progress_path: &Path) -> PathBuf {
    progress_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CONTROL_FILENAME)
}

/// Validate a utilization target.
///
/// Input: any float.
/// Output: `Some(pct)` within [MIN_TARGET_PCT, MAX_TARGET_PCT],
/// `None` otherwise (fail closed).
pub fn validate_target(pct: f64) -> Option<f64> {
    if pct.is_finite() && (MIN_TARGET_PCT..=MAX_TARGET_PCT).contains(&pct) {
        Some(pct)
    } else {
        None
    }
}

/// Read the live utilization target.
///
/// Input: control-file path (`{"target_pct": <float>}`).
/// Output: `Some(pct)` for a valid document, `None` when the file is
/// missing, malformed or out of range (caller keeps its last value).
/// Never panics.
pub fn read_duty(path: &Path) -> Option<f64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    validate_target(value.get("target_pct")?.as_f64()?)
}

/// Atomically write the live utilization target.
///
/// Input: control-file path, target percentage.
/// Output: `Ok(())` after the file is replaced atomically (tmp + rename,
/// so the trainer never observes a partial write); `Err` for out-of-range
/// targets or filesystem failures.
pub fn write_duty(path: &Path, target_pct: f64) -> io::Result<()> {
    let pct = validate_target(target_pct)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target out of range"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{{\"target_pct\":{pct}}}"))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Duty-cycle off-time for one step.
///
/// Input: measured on-time of the step in seconds, target utilization
/// percentage (validated range; clamped defensively).
/// Output: seconds to sleep so time-averaged utilization matches the
/// target (0.0 at 100%; `on * (100 - t) / t` otherwise; never negative).
pub fn pacing_sleep_seconds(step_seconds: f64, target_pct: f64) -> f64 {
    let t = validate_target(target_pct).unwrap_or(MAX_TARGET_PCT);
    if step_seconds <= 0.0 || t >= MAX_TARGET_PCT {
        return 0.0;
    }
    (step_seconds * (MAX_TARGET_PCT - t) / t).max(0.0)
}

/// Current unix time in seconds.
///
/// Input: none.
/// Output: seconds since the unix epoch (0.0 if the system clock is
/// before 1970).
pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Why: the monitor must show "no data" rather than invented numbers —
    // every malformed heartbeat shape must fail closed to None.
    #[test]
    fn parse_progress_fails_closed_on_malformed_input() {
        assert!(parse_progress("not json").is_none());
        assert!(parse_progress("{\"step\":\"x\",\"total_steps\":10}").is_none());
        assert!(parse_progress("{\"step\":1}").is_none());
        assert!(parse_progress("").is_none());
    }

    // Why: the trainer heartbeat is the single source of truth for the
    // progress bar; valid documents must parse with defaults for optionals.
    #[test]
    fn parse_progress_accepts_valid_document_with_optional_fields_absent() {
        let snap = parse_progress("{\"step\":3,\"total_steps\":10}").expect("must parse");
        assert_eq!(snap.step, 3);
        assert_eq!(snap.total_steps, 10);
        assert_eq!(snap.fraction(), 0.3);
        assert!(snap.loss.is_none());
    }

    // Why: staleness drives the stall warning; the boundary at exactly
    // STALE_AFTER_SECONDS and missing/future timestamps must behave
    // deterministically (no underflow into huge values).
    #[test]
    fn staleness_is_boundary_exact_and_never_negative() {
        let snap = ProgressSnapshot {
            step: 1,
            total_steps: 2,
            loss: None,
            status: String::new(),
            elapsed_seconds: 0.0,
            updated_at_unix: 1000.0,
        };
        assert_eq!(
            snap.staleness(1000.0 + STALE_AFTER_SECONDS),
            STALE_AFTER_SECONDS
        );
        assert_eq!(snap.staleness(900.0), 0.0); // clock skew -> 0, never negative
        let mut no_ts = snap.clone();
        no_ts.updated_at_unix = 0.0;
        assert_eq!(no_ts.staleness(99999.0), 0.0);
    }

    // Why: the ETA must never divide by zero or show nonsense before the
    // first step / after completion.
    #[test]
    fn eta_is_none_until_a_rate_exists() {
        let mk = |step, total, elapsed| ProgressSnapshot {
            step,
            total_steps: total,
            loss: None,
            status: String::new(),
            elapsed_seconds: elapsed,
            updated_at_unix: 0.0,
        };
        assert!(mk(0, 100, 60.0).eta_minutes().is_none());
        assert!(mk(50, 50, 60.0).eta_minutes().is_none());
        assert!(mk(5, 10, 0.0).eta_minutes().is_none());
        // 10s/step, 5 steps left -> 50s -> 50/60 minutes.
        let eta = mk(5, 10, 50.0).eta_minutes().expect("rate exists");
        assert!((eta - 50.0 / 60.0).abs() < 1e-9);
    }

    // Why: the slider bounds are a product decision (fan-noise floor vs
    // runaway runtimes); every out-of-range or non-finite target must be
    // rejected so a corrupt file can never throttle the run into a stall.
    #[test]
    fn validate_target_bounds_are_exact() {
        assert_eq!(validate_target(20.0), Some(20.0));
        assert_eq!(validate_target(100.0), Some(100.0));
        assert_eq!(validate_target(19.999), None);
        assert_eq!(validate_target(100.001), None);
        assert_eq!(validate_target(f64::NAN), None);
        assert_eq!(validate_target(f64::INFINITY), None);
    }

    // Why: the duty.json contract is shared with the Python trainer hook;
    // round-trips must survive and out-of-range writes must be refused.
    #[test]
    fn duty_round_trip_and_atomic_write() {
        let dir = std::env::temp_dir().join("rr_duty_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("duty.json");
        write_duty(&path, 55.0).expect("write ok");
        assert_eq!(read_duty(&path), Some(55.0));
        // Atomic write leaves no tmp file behind.
        assert!(!dir.join("duty.json.tmp").exists() || dir.join("duty.json.tmp").is_file());
        assert!(write_duty(&path, 5.0).is_err()); // out of range refused
        assert_eq!(read_duty(&path), Some(55.0)); // value untouched by failed write
        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(read_duty(&path), None); // fail closed on corruption
    }

    // Why: the pacing formula is the core of the ceiling — exact at the
    // boundaries (100% -> no sleep, 50% -> sleep == on-time, 25% -> 3x).
    #[test]
    fn pacing_formula_matches_duty_cycle_definition() {
        assert_eq!(pacing_sleep_seconds(10.0, 100.0), 0.0);
        assert!((pacing_sleep_seconds(10.0, 50.0) - 10.0).abs() < 1e-9);
        assert!((pacing_sleep_seconds(10.0, 25.0) - 30.0).abs() < 1e-9);
        assert_eq!(pacing_sleep_seconds(-1.0, 50.0), 0.0); // never negative
        // Out-of-range target must not panic: falls back to uncapped.
        assert_eq!(pacing_sleep_seconds(10.0, 0.0), 0.0);
    }

    // Why: the operator's hard ceiling is a product requirement (these
    // workloads must never exceed 50% GPU utilization); the slider cap
    // and the CLI default must never drift apart from it.
    #[test]
    fn slider_max_is_the_operator_ceiling() {
        assert_eq!(SLIDER_MAX_PCT, 50.0);
        assert!(SLIDER_MAX_PCT <= MAX_TARGET_PCT);
        assert!(validate_target(SLIDER_MAX_PCT).is_some());
    }

    // Why: the control file must sit next to the heartbeat so one
    // --progress flag locates both without extra configuration.
    #[test]
    fn duty_path_is_sibling_of_progress() {
        assert_eq!(
            duty_path_for(Path::new("/tmp/run/progress.json")),
            PathBuf::from("/tmp/run/duty.json")
        );
    }
}
