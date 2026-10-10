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
import json
import random
import sys
from pathlib import Path

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
        raise SystemExit(f"no known projection modules found; architecture exposes: {sorted(names)[:20]}")
    return found


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", required=True, help="Hugging Face model id or local path")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parent / "data" / "sft_train.jsonl")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda", "hip"), default="auto")
    parser.add_argument("--max-seq-len", type=int, default=2048)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--load-in-4bit", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
    from trl import SFTTrainer

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    device = resolve_device(args.device)

    rows = load_jsonl(args.dataset)
    if not rows:
        print("empty dataset", file=sys.stderr)
        return 2

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

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
        device_map={"": 0} if device == "cuda" else None,
        torch_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float32,
    )
    if args.load_in_4bit:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

    lora = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=discover_target_modules(model),
    )
    model = get_peft_model(model, lora)

    def to_text(row: dict) -> str:
        """Render one chat row as a plain training string.

        Inputs: `row` — a `messages` row. Output: concatenated transcript the
        causal LM learns to continue through the assistant turn.
        """
        return tokenizer.apply_chat_template(row["messages"], tokenize=False)

    args_out = args.output_dir
    args_out.mkdir(parents=True, exist_ok=True)
    train_args = TrainingArguments(
        output_dir=str(args_out / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        logging_steps=10,
        save_strategy="no",
        report_to=[],
        seed=args.seed,
    )
    trainer = SFTTrainer(
        model=model,
        args=train_args,
        train_dataset=Dataset.from_list([{"text": to_text(row)} for row in rows]),
        processing_class=tokenizer,
        formatting_func=None,
    )
    result = trainer.train()

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
    (args_out / "train_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
