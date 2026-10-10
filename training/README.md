# Training toolkit

Host-agnostic fine-tuning and calibration for the rejection-classification
contract. Nothing here is specific to any machine: every path, model and
device is an argument, and the compute device is auto-detected.

## Portability contract

- No absolute paths, usernames, drive letters, GPU models, or container
  assumptions appear in these scripts or their defaults.
- Default paths resolve relative to this directory (`../tests/fixtures/
  rejection_corpus`, `training/data`).
- `--device auto` selects CUDA when available; PyTorch ROCm builds expose the
  same API, so AMD GPUs work through ROCm on Linux or WSL2 on Windows. CPU
  works for small models and for the calibration tools.
- Any base model with LoRA-compatible projection names works (the trainer
  auto-discovers `q_proj`/`k_proj`/`v_proj`/`o_proj`/`gate_proj`/`up_proj`/
  `down_proj` and fails loudly otherwise).

## Supported compute configurations

The trainer itself is device-agnostic, but it can only run where the ML stack
is officially supported for that stack's vendor:

- **CUDA GPUs**: supported by PyTorch on Linux and Windows; `--device auto`
  picks them up directly.
- **AMD ROCm GPUs**: supported by PyTorch on bare-metal Linux with a wheel
  matching the system ROCm release. Verified limitation: on WSL2 the GPU is
  exposed through GPU-PV without KFD topology (`/sys/class/kfd` is absent),
  and the ROCm 7.x runtime's agent initialization requires it, so PyTorch
  ROCm wheels cannot initialize GPU training in WSL2. Use bare-metal Linux
  for ROCm training.
- **AMD ROCm on native Windows**: supported per AMD's Radeon compatibility
  matrix (ROCm 7.2.1 + PyTorch 2.9.1 win_amd64 wheels from repo.radeon.com,
  Python 3.12, Adrenalin 26.2.2+); the RX 9070 XT (gfx1201) row covers both
  runtime and HIP SDK. 9B NF4 QLoRA peaks at roughly 10-12 GB of 16 GB at
  sequence length 2048. Use bitsandbytes ROCm wheels for NF4 or the
  AMD-documented Unsloth Windows stack.
- **CPU**: supported everywhere. Sufficient for pipeline validation and for
  small models; 9B-class training is feasible but slow (~1-2 hours per epoch
  measured on a 16-core CPU).

## Requirements

Python 3.10+, `torch` (your platform's CUDA or ROCm build), `transformers`,
`peft`, `datasets`, `accelerate`, and `bitsandbytes` for 4-bit QLoRA. The
trainer uses the stable `transformers.Trainer` API only, so it runs on every
device without GPU-only kernel dependencies.
For 9B-class models plan on a GPU with at least 16 GiB; smaller models train
on less.

## Zero-false-positive doctrine

A false positive — a non-rejection treated as a rejection — is the critical
error class because it would fire an assertive reply at the wrong message.

1. `build_sft_dataset.py` up-weights hard negatives (emails that superficially
   look like rejections) and keeps the evaluation corpus out of training.
2. `train_lora.py` fine-tunes on that distribution.
3. `calibrate_zero_fp.py` selects the operating threshold with maximal recall
   subject to the observed false-positive target, and reports the binomial
   upper bound so "zero observed" is never mistaken for zero risk.

## Quickstart

```
python training/build_sft_dataset.py
python training/train_lora.py --base-model <HF model id> --output-dir <out>
python training/calibrate_zero_fp.py --scores <scores.jsonl> --target-fp 0
```

Then benchmark the result with the application's own gates
(`rr compare-models`, `rr compare-decision-models`, `rr evaluate-decision`),
which remain the acceptance authority: trained models never bypass the
deterministic rejection gate, the independent verifier, or the exact-signature
check.

Scores for `calibrate_zero_fp.py` are JSONL lines of
`{"label": "rejection"|"not_rejection"|"ambiguous", "rejection_probability": 0..1}`
exported from any model or evaluation run.
