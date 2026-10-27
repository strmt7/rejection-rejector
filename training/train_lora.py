#!/usr/bin/env python3
"""LoRA/QLoRA supervised fine-tuning for the rejection-classification contract.

Host-agnostic and installation-agnostic: the base model, dataset and output
directory are arguments; the compute device is auto-detected (CUDA and ROCm
both expose the CUDA API in PyTorch; CPU works for small models). Nothing in
this script references any specific machine.

The training objective emphasizes the critical error class: the dataset built
by `build_sft_dataset.py` up-weights hard negatives, and final operating-point
selection belongs to `calibrate_zero_fp.py`, not to this script.
"""

from __future__ import annotations

import argparse
import functools
import json
import random
import sys
from pathlib import Path

import duty_cycle
import progress

TARGET_MODULES = (
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",
    "gate_proj",
    "up_proj",
    "down_proj",
)


def resolve_device(requested: str) -> str:
    """Resolve the compute device.

    Inputs: `requested` — one of auto/cpu/cuda (hip maps to cuda because
    PyTorch ROCm exposes the CUDA API). Output: a torch device string; auto
    picks cuda when available, else cpu.
    """
    import torch

    if requested == "cpu":
        return "cpu"
    if requested in ("cuda", "hip"):
        if not torch.cuda.is_available():
            raise SystemExit("requested accelerator is not available in this PyTorch build")
        return "cuda"
    return "cuda" if torch.cuda.is_available() else "cpu"


def discover_target_modules(model) -> list[str]:
    """Discover LoRA target projection names present in the model.

    Inputs: `model` — a loaded causal LM. Output: sorted list of module-name
    suffixes to adapt; raises when the architecture exposes none of the known
    projection names so mis-adaptation fails loudly.
    """
    names = {name.rsplit(".", 1)[-1] for name, _ in model.named_modules()}
    found = [m for m in TARGET_MODULES if m in names]
    if not found:
        raise SystemExit(
            f"no known projection modules found; architecture exposes: {sorted(names)[:20]}"
        )
    return found


def make_causal_collator(tokenizer):
    """Build a dynamic-padding collator for causal-LM labels.

    Inputs: `tokenizer` — the model tokenizer (its `pad` pads `input_ids` and
    `attention_mask`). Output: a callable mapping a list of feature dicts to a
    padded batch where `labels` are padded with -100 so padded positions never
    contribute to the loss.
    """

    def collate(features: list[dict]) -> dict:
        """Pad one batch of tokenized rows.

        Inputs: feature dicts with `input_ids`, `attention_mask`, `labels`.
        Output: the padded batch; labels padded with -100.
        """
        import torch

        labels = [feature["labels"] for feature in features]
        inputs = [
            {
                "input_ids": feature["input_ids"],
                "attention_mask": feature["attention_mask"],
            }
            for feature in features
        ]
        batch = tokenizer.pad(inputs, padding=True, return_tensors="pt")
        width = batch["input_ids"].shape[1]
        batch["labels"] = torch.tensor(
            [label + [-100] * (width - len(label)) for label in labels]
        )
        return batch

    return collate


def load_jsonl(path: Path) -> list[dict]:
    """Load chat-format SFT rows.

    Inputs: `path` — JSONL where each line has a `messages` list. Output: list
    of rows.
    """
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def tokenize_row(row: dict, tokenizer, pad_to_length: int, max_seq_len: int) -> dict:
    """Tokenize one chat row for causal-LM training.

    Inputs: `row` — a `messages` row; `tokenizer` — the model tokenizer;
    `pad_to_length` — fixed token length per row (0 = off); `max_seq_len`
    — truncation bound. Output: dict with `input_ids`, `attention_mask`
    and `labels` (labels mirror `input_ids` so the loss trains on the full
    transcript including the assistant answer). Without `pad_to_length`,
    rows are truncated to `max_seq_len`. With `pad_to_length N`, every row
    becomes EXACTLY N tokens: over-long rows keep the head (subject +
    opening) and the tail (the hiring decision is usually in the closing)
    and drop the middle; short rows are pad-filled with label -100 so
    pads never contribute to the loss. Fixed lengths make GPU bursts
    uniform — the phase-proof guarantee behind the GPU utilization
    ceiling (bursts must stay below half a meter window).
    """
    text = tokenizer.apply_chat_template(row["messages"], tokenize=False)
    if pad_to_length:
        n = pad_to_length
        ids = tokenizer(text)["input_ids"][:max_seq_len]
        if len(ids) > n:
            tail = n // 4
            ids = ids[: n - tail] + ids[-tail:]
        pad_id = tokenizer.pad_token_id
        if pad_id is None:
            pad_id = tokenizer.eos_token_id
        attn = [1] * len(ids) + [0] * (n - len(ids))
        ids = ids + [pad_id] * (n - len(ids))
        labels = [tok if keep else -100 for tok, keep in zip(ids, attn)]
        return {"input_ids": ids, "attention_mask": attn, "labels": labels}
    encoded = tokenizer(text, truncation=True, max_length=max_seq_len)
    encoded["labels"] = list(encoded["input_ids"])
    return encoded


def sample_vram(vram_state: dict) -> None:
    """Record one fresh main-thread VRAM reading.

    Inputs: `vram_state` — shared `{"reading", "at"}` dict. Output: none;
    the dict is updated in place.
    """
    import time as _t

    import torch

    free, total = torch.cuda.mem_get_info()
    vram_state["reading"] = (int(free), int(total))
    vram_state["at"] = _t.time()


def vram_reading_or_raise(vram_state: dict) -> tuple[int, int]:
    """Return the last fresh VRAM reading or fail closed.

    Inputs: `vram_state` — shared `{"reading", "at"}` dict. Output: the
    `(free, total)` reading; raises RuntimeError when no reading fresher
    than 30 seconds exists.
    """
    import time as _t

    reading, at = vram_state["reading"], vram_state["at"]
    if reading is None or _t.time() - at > 30.0:
        raise RuntimeError("no fresh main-thread VRAM reading")
    return reading


def _make_progress_callback(callback_base):
    """Build the heartbeat TrainerCallback class.

    Inputs: `callback_base` — `transformers.TrainerCallback` (kept lazy so
    heavy imports stay inside `main`). Output: the ProgressCallback class.
    """

    class ProgressCallback(callback_base):
        """Training heartbeat for live probing.

        Inputs: `path` — heartbeat file; trainer callbacks receive the run
        state. Output: none; each step atomically writes job, step, total
        steps, latest loss, elapsed seconds and status so
        `training/progress.py` can probe live progress and detect stalls.
        """

        def __init__(self, path: Path, vram_probe=None) -> None:
            import time

            self.path = path
            self.began = time.time()
            self._time = time
            self.vram_probe = vram_probe
            self._probe_errors = 0
            # Cooperative-stop channel (GPU utilization watchdog).
            self.duty_path = duty_cycle.control_path_for(path)

        def on_train_begin(self, args, state, control, **kwargs):
            """Write the initial heartbeat. Inputs: trainer callback args.
            Output: none.
            """
            self._write(state, "running")

        def on_step_end(self, args, state, control, **kwargs):
            """Probe VRAM, drain CUDA, heartbeat and honour stops. Inputs:
            trainer callback args. Output: none.
            """
            # GPU memory queries happen here, on the main thread that owns
            # the GPU work: calling GPU APIs from the watchdog thread races
            # the bridge and intermittently fails or wedges it.
            if self.vram_probe is not None:
                try:
                    self.vram_probe()
                except Exception as exc:
                    # Keep the last reading, but never silence the cause:
                    # rate-limited evidence for root-cause analysis.
                    self._probe_errors += 1
                    if self._probe_errors <= 3 or self._probe_errors % 50 == 0:
                        print(
                            f"resource-guard: vram probe failed "
                            f"({self._probe_errors}x): {exc!r}",
                            file=sys.stderr,
                        )
            # Drain the async GPU queue every step: the known ROCm
            # AsyncEventsLoop spin class (ROCm#6406) builds up in an
            # undrained queue; a per-step synchronize keeps it empty (same
            # mitigation family as pytorch#160759's exit synchronize).
            try:
                import torch

                if torch.cuda.is_available():
                    torch.cuda.synchronize()
            except Exception:
                pass
            self._write(state, "running")
            self._maybe_stop(control)

        def _maybe_stop(self, control) -> None:
            """Honour a cooperative stop request from the control file.

            Input: the trainer `control` (sets `should_training_stop`).
            Output: none. The GPU utilization watchdog (and the operator)
            can request a clean stop via duty.json; the run then ends at
            the next step boundary with checkpoints intact. No signals.
            """
            try:
                if duty_cycle.read_stop_flag(self.duty_path):
                    print(
                        "resource-guard: cooperative stop requested via duty control file",
                        file=sys.stderr,
                    )
                    control.should_training_stop = True
            except Exception as exc:
                print(f"resource-guard: stop-flag check failed: {exc!r}", file=sys.stderr)

        def on_train_end(self, args, state, control, **kwargs):
            """Write the terminal heartbeat. Inputs: trainer callback args.
            Output: none.
            """
            self._write(state, "complete")

        def _write(self, state, status: str) -> None:
            """Atomically persist one heartbeat record. Inputs: trainer run
            `state` and the status string. Output: none.
            """
            now = self._time.time()
            step = int(state.global_step)
            record = {
                "job": "train_lora",
                "step": step,
                "total_steps": int(state.max_steps or 0),
                "loss": state.log_history[-1].get("loss") if state.log_history else None,
                "elapsed_seconds": now - self.began,
                "updated_at_unix": now,
                "status": status,
            }
            progress.write_progress(self.path, record)

    return ProgressCallback


def _make_paced_trainer(trainer_base):
    """Build the duty-paced Trainer subclass.

    Inputs: `trainer_base` — `transformers.Trainer` (kept lazy so heavy
    imports stay inside `main`). Output: the PacedTrainer class.
    """

    class PacedTrainer(trainer_base):
        """Trainer with GPU-burst pacing between micro-batches.

        The GPU utilization ceiling is enforced at MICRO-BATCH granularity:
        before every training_step (each gradient-accumulation unit) the
        trainer sleeps the duty-cycle off-time computed from the PREVIOUS
        micro-batch's measured duration and the live duty.json target.
        This chops GPU work into one-micro-batch bursts instead of whole-
        optimizer-step runs, which is what per-second GPU meters (the
        Windows GPU Engine counters Task Manager displays) require to stay
        within the ceiling. Pure host-side sleeping: no driver, fan, clock
        or power interaction. Fail-closed: a missing/corrupt control file
        falls back to the CLI-seeded target (throttle, never uncapped).
        """

        def __init__(self, *args, duty_path, seed_target, progress_path, **kwargs):
            super().__init__(*args, **kwargs)
            self.duty_path = duty_path
            self.seed_target = duty_cycle.validate_target_pct(seed_target)
            self.progress_path = progress_path
            # Robust pacing baseline: median of recent micro-batch
            # on-times (a one-time Triton-JIT spike or a variable-length
            # batch cannot skew the sleep the way a mean or a growth cap
            # does — the cap under-slept on variable batches and the raw
            # mean over-slept after JIT; both were verified wrong live).
            self._recent_on: list[float] = []
            self._step_index = 0

        def training_step(self, *args, **kwargs):
            """Run one micro-batch behind the duty-cycle pacing.

            Input: passthrough to `Trainer::training_step`.
            Output: the micro-batch loss (unchanged semantics; pacing is
            pure host-side sleeping before the call).
            """
            import os
            import time as _t

            try:
                if duty_cycle.read_stop_flag(self.duty_path):
                    print(
                        "resource-guard: cooperative stop requested via duty control file",
                        file=sys.stderr,
                    )
                    self.control.should_training_stop = True
            except Exception as exc:
                print(f"resource-guard: stop-flag check failed: {exc!r}", file=sys.stderr)
            try:
                target = duty_cycle.read_target(self.duty_path)
                if target is None:
                    target = self.seed_target
                if self._recent_on:
                    # P90 baseline (not median): on a shared GPU the
                    # desktop occasionally stretches bursts; pacing
                    # against the 90th percentile is conservative and
                    # keeps even stretched windows under the ceiling.
                    ordered = sorted(self._recent_on)
                    baseline = ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))]
                    off = duty_cycle.sleep_seconds(baseline, target)
                    if off > 0.0:
                        # Sliced sleep with heartbeat touches so the
                        # stall instruments stay quiet during pacing.
                        duty_cycle.paced_sleep(
                            off,
                            touch=lambda: os.utime(self.progress_path),
                        )
            except Exception as exc:
                print(f"resource-guard: micro-batch pacing skipped: {exc!r}", file=sys.stderr)
            t0 = _t.perf_counter()
            loss = super().training_step(*args, **kwargs)
            measured = _t.perf_counter() - t0
            self._recent_on.append(measured)
            if len(self._recent_on) > 8:
                self._recent_on.pop(0)
            # Durable per-micro-batch evidence: the operator's GPU
            # utilization ceiling must be verifiable from logs, not
            # taken on faith.
            self._step_index += 1
            try:
                with self.progress_path.parent.joinpath("pace-log.jsonl").open(
                    "a", encoding="utf-8"
                ) as fh:
                    fh.write(
                        json.dumps(
                            {
                                "step": self._step_index,
                                "on_s": round(measured, 4),
                                "target_pct": duty_cycle.read_target(self.duty_path),
                            }
                        )
                        + "\n"
                    )
            except Exception:
                pass
            return loss

    return PacedTrainer


def _place(module, load_target: float) -> None:
    """Move one leaf module to cuda with duty sleeps between moves.

    Inputs: `module` — model or submodule (recursed to its leaves);
    `load_target` — validated utilization target for the move pacing.
    Output: none; each leaf is moved to cuda with a duty sleep after it.
    """
    import time as _tl

    import torch

    children = list(module.children())
    if children:
        for child in children:
            _place(child, load_target)
        return
    started = _tl.perf_counter()
    module.to("cuda")
    torch.cuda.synchronize()
    on_time = _tl.perf_counter() - started
    duty_cycle.paced_sleep(duty_cycle.sleep_seconds(on_time, load_target))


def _load_model(args, device: str, pace_load: bool):
    """Quantize, load and optionally pace-place the causal LM.

    Inputs: parsed CLI args, resolved device string, and whether paced GPU
    placement applies. Output: the loaded model on its target device.
    """
    import time as _tl

    import torch
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig

    quant = None
    if args.load_in_4bit:
        compute = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute,
        )
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=quant,
        device_map={"": "cpu"} if pace_load else ({"": 0} if device == "cuda" else None),
        dtype=torch.bfloat16 if (args.bf16 or torch.cuda.is_bf16_supported()) else torch.float32,
    )
    if pace_load:
        # Paced GPU placement: a direct device_map={"": 0} load produces
        # minutes of un-throttled GPU bursts that breach the utilization
        # ceiling (verified live: the meter watchdog stopped every attempt
        # inside its load phase). Load to CPU first, then move leaf modules
        # one at a time with duty sleeps between — each burst is a single
        # module move (~20-100ms), each gap follows the same duty formula
        # as training steps.
        load_target = duty_cycle.validate_target_pct(args.max_gpu_utilization)
        _place(model, load_target)
        # Completeness catch-all: leaf placement above is paced per leaf module,
        # but a non-leaf module can carry its own direct parameters or buffers
        # (rotary tables, causal-conv state, attention masks) that leaf-only
        # recursion never touches. `model.to` moves any remaining CPU tensors
        # with proper PyTorch semantics (preserves weight tying, moves
        # bitsandbytes quant_state); already-placed tensors are cheap no-ops.
        # This closes the placement gap the device assert below verifies.
        model.to("cuda")
        torch.cuda.synchronize()
        leftovers = sorted(
            {str(p.device) for p in model.parameters()}
            | {str(b.device) for b in model.buffers()}
        )
        if leftovers != ["cuda:0"]:
            raise RuntimeError(
                f"paced load must land every parameter/buffer on cuda:0; "
                f"devices seen: {leftovers}"
            )
    return model


def _prepare_kbit(model, args) -> None:
    """Prepare a 4-bit model for LoRA training with a lean fp32 peak.

    Inputs: `model` (modified in place), parsed CLI args. Output: none.
    """
    import torch
    from peft import prepare_model_for_kbit_training

    if args.bf16:
        # Memory-lean path: peft's prepare casts embeddings/lm-head to
        # fp32 (~3.8 GiB peak), which OOMs a 16 GiB GPU immediately after
        # load. In bf16 mode skip that cast and enable checkpointing
        # directly; inputs require grads for LoRA and activations stay
        # checkpointed, so training is stable without the fp32 peak.
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    else:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    # peft's prepare casts every non-quantized parameter to fp32; on a
    # 16 GiB GPU the embeddings/lm-head cast alone peaks ~3.8 GiB and
    # OOMs right after load. Norms stay fp32 (stability), but the large
    # tensors are held in the compute dtype, halving that peak. Inputs:
    # `model` (in place). Output: none.
    for _name, param in model.named_parameters():
        if param.dtype == torch.float32 and param.numel() > 10_000_000:
            target = (
                torch.bfloat16
                if (args.bf16 or torch.cuda.is_bf16_supported())
                else torch.float16
            )
            param.data = param.data.to(target)


def stop_on_resource_breach(trainer, v) -> None:
    """Stop training before any resource limit is reached. Inputs:
    `trainer` — the live trainer; `v` — the first guard violation. Output:
    none; sets the trainer's cooperative stop flag so the run ends cleanly
    and the adapter checkpoint from the last completed step survives.
    """
    print(
        f"resource-guard: stopping training: {v.resource}: "
        f"{v.reason}: {v.detail}",
        file=sys.stderr,
    )
    trainer.control.should_training_stop = True


def stall_watchdog(progress_path: Path) -> None:
    """Dump all thread stacks and exit 97 when the heartbeat goes stale.

    Input: `progress_path` — the heartbeat file whose mtime is watched.
    Output: none (daemon thread body; never returns).
    """
    import faulthandler
    import os as _os
    import time as _t

    dumped = False
    while True:
        _t.sleep(30)
        try:
            age = _t.time() - progress_path.stat().st_mtime
        except OSError:
            continue
        if age > 120.0 and not dumped:
            dumped = True
            print(
                f"resource-guard: STALLED {age:.0f}s (heartbeat stale "
                f"mid-run); dumping all thread stacks",
                file=sys.stderr,
            )
            faulthandler.dump_traceback(file=sys.stderr)
            _t.sleep(10)  # let the dump flush through tee
            _os._exit(97)


def _warmup(model) -> None:
    """Warm the CUDA allocator and common kernels with tiny bursts.

    Input: `model` — the loaded model. Output: none; failures are reported
    and skipped, never fatal.
    """
    import time as _tw

    import torch

    # Warmup passes: warm the CUDA allocator and the common kernels with
    # TINY bursts (<50ms each) so the first paced micro-batches are not
    # inflated — a resume previously produced 0.6-0.7s warmup bursts that
    # breached the utilization ceiling (verified in pace-log evidence).
    try:
        warm_ids = torch.zeros((1, 16), dtype=torch.long, device=model.device)
        for _ in range(3):
            out = model(input_ids=warm_ids, labels=warm_ids)
            out.loss.backward()
            model.zero_grad(set_to_none=True)
            torch.cuda.synchronize()
            _tw.sleep(0.3)
    except Exception as exc:
        print(f"resource-guard: warmup skipped: {exc!r}", file=sys.stderr)


def main() -> int:
    """Fine-tune a LoRA/QLoRA adapter on the FP-weighted SFT dataset.

    Inputs: argv (base model, dataset, output directory, device, pacing
    and training knobs). Output: exit status 0 on success, 2 when the
    resource gate refuses to start or the dataset is empty; writes the
    adapter, tokenizer, checkpoints and train_report.json.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", required=True, help="Hugging Face model id or local path")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "sft_train.jsonl",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda", "hip"), default="auto")
    parser.add_argument("--max-seq-len", type=int, default=2048)
    parser.add_argument(
        "--pad-to-length", type=int, default=0,
        help="Fixed token length per row (0 = off): over-long rows keep "
             "head+tail, short rows pad with label -100. Uniform lengths "
             "give uniform GPU bursts, required by the utilization ceiling",
    )
    parser.add_argument(
        "--pace-load", action=argparse.BooleanOptionalAction, default=True,
        help="Place the model onto the GPU leaf-module by leaf-module with "
             "duty sleeps between moves (a direct device_map load produces "
             "minutes of un-throttled bursts that breach the utilization "
             "ceiling; verified live). Disable only for non-metered hosts",
    )
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--model-billions", type=float, default=9.0,
        help="Base model size in billions of parameters; used only by the "
             "fail-closed resource guard to estimate peak VRAM before start",
    )
    parser.add_argument(
        "--resume", type=Path, default=None,
        help="Checkpoint directory to resume from (Trainer resume_from_checkpoint)",
    )
    parser.add_argument(
        "--max-gpu-utilization", type=float, default=100.0,
        help="GPU utilization ceiling in percent (20-100): enforced purely "
             "by pacing this loop's own steps (duty-cycle sleeps), never via "
             "driver/fan/clock/power controls. Seeded into duty.json when "
             "absent; the monitor GUI tunes it live mid-run",
    )
    parser.add_argument(
        "--bf16", action="store_true", help="Use bfloat16 compute where the platform supports it"
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        help="Heartbeat JSON for live probing (default: output-dir/progress.json)",
    )
    parser.add_argument("--load-in-4bit", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoTokenizer,
        Trainer,
        TrainingArguments,
        TrainerCallback,
    )

    # The callback contract: ProgressCallback subclasses TrainerCallback.
    ProgressCallback = _make_progress_callback(TrainerCallback)

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    device = resolve_device(args.device)

    # Fail-closed resource gate: never start a run that could push VRAM, RAM
    # or storage toward a limit. tools/resource_guard.py is exhaustively
    # tested and its peak estimator is deliberately pessimistic, so an
    # under-sized host refuses to start instead of crashing mid-run.
    args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import resource_guard as rg

    need = rg.estimate_training_vram(
        param_billions=args.model_billions, seq_len=args.max_seq_len
    )
    gate = rg.preflight(
        limits=rg.Thresholds(min_free_vram=need, require_vram=device == "cuda"),
        disk_path=str(args.output_dir.parent),
    )
    if not gate.ok:
        for violation in gate.violations:
            print(
                f"resource-guard: {violation.resource}: "
                f"{violation.reason}: {violation.detail}",
                file=sys.stderr,
            )
        print("resource-guard: refusing to start (fail-closed)", file=sys.stderr)
        return 2

    rows = load_jsonl(args.dataset)
    if not rows:
        print("empty dataset", file=sys.stderr)
        return 2

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    pace_load = device == "cuda" and args.pace_load
    model = _load_model(args, device, pace_load)
    if args.load_in_4bit:
        _prepare_kbit(model, args)

    lora = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=discover_target_modules(model),
    )
    model = get_peft_model(model, lora)

    args_out = args.output_dir
    args_out.mkdir(parents=True, exist_ok=True)
    train_args = TrainingArguments(
        output_dir=str(args_out / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        logging_steps=10,
        save_strategy="steps",
        save_steps=25,
        save_total_limit=2,
        report_to=[],
        seed=args.seed,
        use_cpu=device == "cpu",
        bf16=args.bf16,
        # Resume robustness: skip HF's dataloader fast-forward on resume. That
        # fast-forward can mis-advance the data stream; restarting it is the
        # supported way to avoid skip-overshoot. NOTE: a separate observed
        # issue is that resume-from-checkpoint can report 0 steps and exit at
        # the resumed epoch (root cause not yet isolated); a fresh run (no
        # --resume) trains to completion. See docs/LESSONS.md.
        ignore_data_skip=True,
    )
    vram_state = {"reading": None, "at": 0.0}

    PacedTrainer = _make_paced_trainer(Trainer)

    progress_path = args.progress_file or (args_out / "progress.json")
    # Seed the duty control file only when absent: a monitor-chosen ceiling
    # must SURVIVE a resume (the live value wins over the CLI default).
    duty_path = duty_cycle.control_path_for(progress_path)
    if duty_cycle.read_target(duty_path) is None:
        duty_cycle.write_target(
            duty_path, duty_cycle.validate_target_pct(args.max_gpu_utilization)
        )
    trainer = PacedTrainer(
        model=model,
        args=train_args,
        train_dataset=Dataset.from_list([
            tokenize_row(row, tokenizer, args.pad_to_length, args.max_seq_len) for row in rows
        ]),
        data_collator=make_causal_collator(tokenizer),
        duty_path=duty_path,
        seed_target=args.max_gpu_utilization,
        progress_path=progress_path,
        callbacks=[ProgressCallback(
            progress_path,
            vram_probe=functools.partial(sample_vram, vram_state),
        )],
    )

    # Mid-step stall instrument: the trainer callback only runs between
    # steps, so a wedge INSIDE a step is invisible to it. This daemon watch
    # the heartbeat file's mtime instead and dumps every thread's stack when
    # it goes stale, then exits with code 97 so a wrapper loop can resume
    # from the latest checkpoint (a wedge costs one checkpoint interval).
    threading_mod = __import__("threading")
    threading_mod.Thread(
        target=functools.partial(stall_watchdog, progress_path), daemon=True
    ).start()

    _warmup(model)

    # Continuous observation: a second process eating VRAM/RAM, or runaway
    # output growth, ends the run BEFORE anything approaches a limit.
    with rg.ResourceWatchdog(
        limits=rg.Thresholds(require_vram=device == "cuda"),
        soft_resources=frozenset({"vram"}),
        vram_probe=functools.partial(vram_reading_or_raise, vram_state),
        on_violation=functools.partial(stop_on_resource_breach, trainer),
        disk_path=str(args.output_dir.parent),
    ):
        result = trainer.train(resume_from_checkpoint=str(args.resume) if args.resume else None)
    # Termination fix for ROCm process hangs: an explicit synchronize lets
    # the runtime wind down (pytorch/pytorch#160759).
    if device == "cuda":
        torch.cuda.synchronize()

    model.save_pretrained(args_out)
    tokenizer.save_pretrained(args_out)
    report = {
        "base_model": args.base_model,
        "dataset": str(args.dataset),
        "rows": len(rows),
        "device": device,
        "load_in_4bit": args.load_in_4bit,
        "train_loss": result.training_loss,
        "torch": torch.__version__,
        "seed": args.seed,
    }
    (args_out / "train_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
