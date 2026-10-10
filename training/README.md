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

## Requirements

Python 3.10+, `torch` (your platform's CUDA or ROCm build), `transformers`,
`peft`, `trl`, `datasets`, `accelerate`, and `bitsandbytes` for 4-bit QLoRA.
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
