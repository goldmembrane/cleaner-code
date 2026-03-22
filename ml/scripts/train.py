"""
Fine-tune CodeBERT for malicious code detection.
Binary classification: malicious (1) vs benign (0).
"""

import os
import json
import torch
import numpy as np
from pathlib import Path
from torch.utils.data import Dataset, DataLoader
from transformers import (
    RobertaTokenizer,
    RobertaForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)

# --- Config ---
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
MODEL_NAME = "microsoft/codebert-base"
MAX_LENGTH = 256
BATCH_SIZE = 16
EPOCHS = 5
LEARNING_RATE = 2e-5
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class CodeDataset(Dataset):
    def __init__(self, file_path, tokenizer, max_length):
        self.samples = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                self.samples.append(json.loads(line))
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        encoding = self.tokenizer(
            sample["code"],
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
            "label": torch.tensor(sample["label"], dtype=torch.long),
        }


def evaluate(model, dataloader, device):
    model.eval()
    all_preds = []
    all_labels = []
    total_loss = 0

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                labels=labels,
            )
            total_loss += outputs.loss.item()

            preds = torch.argmax(outputs.logits, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    avg_loss = total_loss / len(dataloader)
    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        all_labels, all_preds, average="binary"
    )

    return {
        "loss": avg_loss,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "predictions": all_preds,
        "labels": all_labels,
    }


def main():
    print(f"Device: {DEVICE}")
    print(f"Model: {MODEL_NAME}")
    print()

    # Load tokenizer
    print("Loading tokenizer...")
    tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME)

    # Load datasets
    print("Loading datasets...")
    train_dataset = CodeDataset(DATA_DIR / "train.jsonl", tokenizer, MAX_LENGTH)
    val_dataset = CodeDataset(DATA_DIR / "val.jsonl", tokenizer, MAX_LENGTH)
    test_dataset = CodeDataset(DATA_DIR / "test.jsonl", tokenizer, MAX_LENGTH)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)

    print(f"  Train: {len(train_dataset)} samples")
    print(f"  Val:   {len(val_dataset)} samples")
    print(f"  Test:  {len(test_dataset)} samples")
    print()

    # Load model
    print("Loading CodeBERT model...")
    model = RobertaForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
    )
    model.to(DEVICE)

    # Optimizer & scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    total_steps = len(train_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * 0.1),
        num_training_steps=total_steps,
    )

    # Training loop
    best_f1 = 0
    print("Starting training...")
    print("=" * 60)

    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0
        batch_count = 0

        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            labels = batch["label"].to(DEVICE)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                labels=labels,
            )

            loss = outputs.loss
            total_loss += loss.item()
            batch_count += 1

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            if (batch_idx + 1) % 50 == 0:
                avg = total_loss / batch_count
                print(f"  Epoch {epoch+1}/{EPOCHS} | Batch {batch_idx+1}/{len(train_loader)} | Loss: {avg:.4f}")

        # Validation
        val_metrics = evaluate(model, val_loader, DEVICE)
        print(f"\n  Epoch {epoch+1} Results:")
        print(f"    Train Loss: {total_loss/batch_count:.4f}")
        print(f"    Val Loss:   {val_metrics['loss']:.4f}")
        print(f"    Val Acc:    {val_metrics['accuracy']:.4f}")
        print(f"    Val F1:     {val_metrics['f1']:.4f}")
        print(f"    Val Prec:   {val_metrics['precision']:.4f}")
        print(f"    Val Recall: {val_metrics['recall']:.4f}")
        print()

        # Save best model
        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            save_path = MODEL_DIR / "best"
            os.makedirs(save_path, exist_ok=True)
            model.save_pretrained(save_path)
            tokenizer.save_pretrained(save_path)
            print(f"    ★ Best model saved (F1: {best_f1:.4f})")
            print()

    # Final test evaluation
    print("=" * 60)
    print("Loading best model for test evaluation...")
    model = RobertaForSequenceClassification.from_pretrained(MODEL_DIR / "best")
    model.to(DEVICE)

    test_metrics = evaluate(model, test_loader, DEVICE)
    print(f"\nTest Results:")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1 Score:  {test_metrics['f1']:.4f}")
    print()

    # Confusion matrix
    cm = confusion_matrix(test_metrics["labels"], test_metrics["predictions"])
    print("Confusion Matrix:")
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")
    print()

    # Full report
    print("Classification Report:")
    print(
        classification_report(
            test_metrics["labels"],
            test_metrics["predictions"],
            target_names=["benign", "malicious"],
        )
    )

    # Save test metrics
    metrics_path = MODEL_DIR / "test_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(
            {
                "accuracy": test_metrics["accuracy"],
                "precision": test_metrics["precision"],
                "recall": test_metrics["recall"],
                "f1": test_metrics["f1"],
                "confusion_matrix": cm.tolist(),
            },
            f,
            indent=2,
        )
    print(f"Test metrics saved to {metrics_path}")


if __name__ == "__main__":
    main()
