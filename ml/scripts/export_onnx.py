"""
Export the trained CodeBERT model to ONNX format for use in Node.js.
"""

import os
import torch
from pathlib import Path
from transformers import RobertaTokenizer, RobertaForSequenceClassification

BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = BASE_DIR / "models" / "best"
ONNX_DIR = BASE_DIR / "models" / "onnx"
MAX_LENGTH = 256


def main():
    print("Loading trained model...")
    model = RobertaForSequenceClassification.from_pretrained(MODEL_DIR)
    tokenizer = RobertaTokenizer.from_pretrained(MODEL_DIR)
    model.eval()

    # Create dummy input
    dummy_text = "const x = 1;"
    inputs = tokenizer(
        dummy_text,
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
    )

    os.makedirs(ONNX_DIR, exist_ok=True)
    onnx_path = ONNX_DIR / "model.onnx"

    print(f"Exporting to ONNX: {onnx_path}")
    torch.onnx.export(
        model,
        (inputs["input_ids"], inputs["attention_mask"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
        do_constant_folding=True,
    )

    # Verify
    import onnxruntime as ort
    import numpy as np

    session = ort.InferenceSession(str(onnx_path))
    ort_inputs = {
        "input_ids": inputs["input_ids"].numpy(),
        "attention_mask": inputs["attention_mask"].numpy(),
    }
    ort_outputs = session.run(None, ort_inputs)

    # Compare with PyTorch output
    with torch.no_grad():
        pt_outputs = model(**inputs)

    pt_logits = pt_outputs.logits.numpy()
    ort_logits = ort_outputs[0]

    diff = np.abs(pt_logits - ort_logits).max()
    print(f"Max difference between PyTorch and ONNX: {diff:.6f}")
    print(f"ONNX export {'successful' if diff < 0.001 else 'FAILED - outputs differ'}!")

    # Save tokenizer vocab for Node.js
    tokenizer.save_pretrained(ONNX_DIR)
    print(f"Tokenizer saved to {ONNX_DIR}")

    # Model size
    size_mb = os.path.getsize(onnx_path) / (1024 * 1024)
    print(f"ONNX model size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
