#!/usr/bin/env bash
# Guarded training chain: one launch, zero unprotected windows.
#
# For every training attempt this chain:
#   1. starts the GPU utilization watchdog FIRST (ceiling enforcement armed
#      before any GPU work exists),
#   2. runs one training attempt (self-healing inside: stall/OOM exit
#      codes 97/137 resume from the latest checkpoint),
#   3. stops the watchdog, and
#   4. RETRIES with a cooldown when the watchdog stopped the run
#      (duty.json carries {"stop": true}): on a shared GPU the desktop
#      stretches bursts and occasional meter samples reach the ceiling;
#      the absolute policy stops the workload instantly, and progress
#      resumes automatically whenever a compliant window exists.
#
# The operator's ceiling is absolute: training pauses are always preferred
# over ceiling violations. Evidence per attempt lands in
# training-runs/gpu-util-watch.jsonl and pace-log.jsonl.
set -u

RUN_DIR="/mnt/c/Users/strat/projects/rr/training-runs/mimo-9b-lora-v2data"
REPO="/mnt/c/Users/strat/projects/rr/canonical"
PY="$HOME/rr-gpu10/bin/python"
MAX_ATTEMPTS="${1:-8}"

export HSA_ENABLE_DXG_DETECTION=1
export PYTORCH_HIP_ALLOC_CONF=garbage_collection_threshold:0.8
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1

cd "$REPO" || exit 1
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    CKPT=$(ls -d "$RUN_DIR"/checkpoints/checkpoint-* 2>/dev/null | sort -t- -k2 -n | tail -1)
    echo "=== attempt $attempt from ${CKPT:-scratch} ==="
    rm -f "$RUN_DIR/duty.json"

    # 1. Enforcement armed BEFORE any GPU work.
    python tools/gpu_util_watchdog.py \
        --match-name vmwp,vmmem,wslrelay \
        --duty "$RUN_DIR/duty.json" \
        --ceiling 50 \
        --log /mnt/c/Users/strat/projects/rr/training-runs/gpu-util-watch.jsonl &
    WATCHDOG=$!

    # 2. One training attempt.
    "$PY" training/train_lora.py \
        --base-model XiaomiMiMo/MiMo-V2.6-Distill-Qwen-9B \
        --dataset training/data/sft_train_v2.jsonl \
        --output-dir "$RUN_DIR" \
        --device cuda --bf16 \
        --lora-rank 16 --lora-alpha 32 \
        --max-seq-len 512 --pad-to-length 128 \
        --epochs 3 --batch-size 1 --grad-accum 32 \
        --learning-rate 2e-4 --model-billions 9 \
        --max-gpu-utilization 25 \
        ${CKPT:+--resume "$CKPT"} \
        2>&1 | tee /mnt/c/Users/strat/projects/rr/training-runs/train-v2data.log
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
    # Anything else — watchdog ceiling stop, stall self-heal (97/137), OOM,
    # or a transient GPU-link death (verified case: dxgkrnl ioctl -512 killed
    # the CUDA process mid-step; classified as transient, must retry) — is
    # retried with a cooldown. MAX_ATTEMPTS bounds genuine hard failures.
    echo "retrying-after-cooldown (exit $CODE)"
    sleep 90
done
echo "guarded-chain-finished"
