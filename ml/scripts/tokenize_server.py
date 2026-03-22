"""
Simple stdin/stdout tokenizer bridge for Node.js.
Reads JSON lines from stdin, outputs tokenized results.
"""

import sys
import json
from transformers import AutoTokenizer

MAX_LENGTH = 256

def main():
    tokenizer = AutoTokenizer.from_pretrained(
        sys.argv[1] if len(sys.argv) > 1 else "ml/models/onnx"
    )

    # Signal ready
    sys.stdout.write(json.dumps({"status": "ready"}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            text = request.get("text", "")

            encoding = tokenizer(
                text,
                truncation=True,
                padding="max_length",
                max_length=MAX_LENGTH,
                return_tensors=None,
            )

            result = {
                "input_ids": encoding["input_ids"],
                "attention_mask": encoding["attention_mask"],
            }
            sys.stdout.write(json.dumps(result) + "\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
