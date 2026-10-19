#!/usr/bin/env bash
# Guarded training chain: one launch, zero unprotected windows.
#
# For every training attempt this chain:
#   1. starts the GPU utilization watchdog FIRST (ceiling enforcement armed
#      before any GPU work exists),
#   2. runs one training attempt (self-healing inside: stall/OOM exit
#      codes 97/137 resume from the latest checkpoint),
#   3. stops the watchdog, and
#   4. RETRIES with a cooldown on watchdog ceiling stops and transient
#      failures (including GPU-link deaths); only configuration errors
#      (exit 2) are not retried.
#
# HOST-AGNOSTIC & FULLY AUTOMATIC: every path, interpreter, and limit is
# auto-detected or overridable via environment variables. Nothing about a
# specific machine (paths, usernames, drive letters, GPU model, thread or
# memory limits) is baked in, so this runs unmodified on any compatible host.
#
# Environment knobs (all optional):
#   RR_REPO_ROOT       repo root                  (default: parent of this script)
#   RR_PYTHON          python interpreter         (default: python3, else python)
#   RR_RUN_NAME        run/output folder name     (default: mimo-9b-lora-v2data)
#   RR_TRAIN_RUN_DIR   absolute runs directory    (default: <repo>/../training-runs)
#   RR_GPU_CEILING     max GPU utilization percent(default: 50)
#   RR_GPU_MATCH       watchdog process-name match(default: auto-detected)
#   RR_MAX_ATTEMPTS    retry budget               (default: 8)
#   RR_RETRY_COOLDOWN  seconds between retries    (default: 90)
#   RR_BASE_MODEL, RR_DATASET, RR_LORA_RANK, RR_LORA_ALPHA, RR_MAX_SEQ_LEN,
#   RR_PAD_TO, RR_EPOCHS, RR_BATCH, RR_GRAD_ACCUM, RR_LR, RR_MODEL_B,
#   RR_TRAIN_DUTY      training hyper-parameters  (sensible defaults below)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${RR_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PY="${RR_PYTHON:-$(command -v python3 2>/dev/null || command -v python 2>/dev/null)}"
RUN_NAME="${RR_RUN_NAME:-mimo-9b-lora-v2data}"
RUNS_BASE="${RR_TRAIN_RUN_DIR:-$REPO/../training-runs}"
RUN_DIR="$RUNS_BASE/$RUN_NAME"
WATCH_LOG="$RUNS_BASE/gpu-util-watch.jsonl"
TRAIN_LOG="$RUNS_BASE/train-$RUN_NAME.log"
CEILING="${RR_GPU_CEILING:-50}"
MAX_ATTEMPTS="${RR_MAX_ATTEMPTS:-8}"

# Watchdog process-name match: auto-detect a WSL/Windows GPU-paravirt VM,
# otherwise leave empty so the watchdog selects by itself.
if [ -n "${RR_GPU_MATCH:-}" ]; then
    MATCH_NAME="$RR_GPU_MATCH"
elif [ -d /mnt/c ] && command -v powershell.exe >/dev/null 2>&1; then
    MATCH_NAME="vmwp,vmmem,wslrelay"
else
    MATCH_NAME=""
fi

# Tuning is applied only when the caller has not already chosen a value
# (non-invasive: never overrides an existing environment configuration).
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"
export PYTORCH_HIP_ALLOC_CONF="${PYTORCH_HIP_ALLOC_CONF:-garbage_collection_threshold:0.8}"
# ROCm-in-WSL hint; ignored on non-ROCm hosts.
export HSA_ENABLE_DXG_DETECTION="${HSA_ENABLE_DXG_DETECTION:-1}"

mkdir -p "$RUN_DIR"
cd "$REPO" || exit 1

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    CKPT=$(ls -d "$RUN_DIR"/checkpoints/checkpoint-* 2>/dev/null | sort -t- -k2 -n | tail -1)
    echo "=== attempt $attempt from ${CKPT:-scratch} ==="
    rm -f "$RUN_DIR/duty.json"

    # 1. Enforcement armed BEFORE any GPU work.
    "$PY" tools/gpu_util_watchdog.py \
        ${MATCH_NAME:+--match-name "$MATCH_NAME"} \
        --duty "$RUN_DIR/duty.json" \
        --ceiling "$CEILING" \
        --log "$WATCH_LOG" &
    WATCHDOG=$!

    # 2. One training attempt.
    "$PY" training/train_lora.py \
        --base-model "${RR_BASE_MODEL:-XiaomiMiMo/MiMo-V2.6-Distill-Qwen-9B}" \
        --dataset "${RR_DATASET:-training/data/sft_train_v2.jsonl}" \
        --output-dir "$RUN_DIR" \
        --device cuda --bf16 \
        --lora-rank "${RR_LORA_RANK:-16}" --lora-alpha "${RR_LORA_ALPHA:-32}" \
        --max-seq-len "${RR_MAX_SEQ_LEN:-512}" --pad-to-length "${RR_PAD_TO:-128}" \
        --epochs "${RR_EPOCHS:-3}" --batch-size "${RR_BATCH:-1}" --grad-accum "${RR_GRAD_ACCUM:-32}" \
        --learning-rate "${RR_LR:-2e-4}" --model-billions "${RR_MODEL_B:-9}" \
        --max-gpu-utilization "${RR_TRAIN_DUTY:-25}" \
        ${CKPT:+--resume "$CKPT"} \
        2>&1 | tee "$TRAIN_LOG"
    CODE=${PIPESTATUS[0]}
    echo "attempt-exit=$CODE"

    # 3. Enforcement off; classify the outcome.
    kill "$WATCHDOG" 2>/dev/null
    wait "$WATCHDOG" 2>/dev/null

    if [ "$CODE" = "0" ] && ! grep -q '"stop": true' "$RUN_DIR/duty.json" 2>/dev/null; then
        echo "run-complete-cleanly"
        break
    fi
    if [ "$CODE" = "2" ]; then
        echo "configuration-error-exit=2 (not retried: fix args/dataset first)"
        break
    fi
    # Watchdog ceiling stop, stall self-heal (97/137), OOM, or a transient
    # GPU-link death (verified case: dxgkrnl ioctl -512 killed CUDA mid-step):
    # all retried with a cooldown. MAX_ATTEMPTS bounds genuine hard failures.
    echo "retrying-after-cooldown (exit $CODE)"
    sleep "${RR_RETRY_COOLDOWN:-90}"
done
echo "guarded-chain-finished"
