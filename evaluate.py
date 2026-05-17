"""
evaluate.py — Batch evaluation of the phishing detection agent
against the archive dataset.

Usage:
    python evaluate.py [--samples N] [--dataset PATH]

Defaults:
    --samples  100  (50 safe + 50 phishing)
    --dataset  ../archive/phishing_email.csv
"""

import argparse
import csv
import json
import os
import random
import sys
import time
from collections import Counter

# ── path setup so we can import agent from sibling location ──────────────────
sys.path.insert(0, os.path.dirname(__file__))
from agent import analyse_email

csv.field_size_limit(10_000_000)

# ─────────────────────────────────────────────────────────────────────────────
DATASET_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "archive", "phishing_email.csv"
)

RESULTS_CSV = os.path.join(os.path.dirname(__file__), "evaluate_results.csv")
METRICS_JSON = os.path.join(os.path.dirname(__file__), "evaluate_metrics.json")

# Groq free tier: 30 requests / minute → sleep ~2.1 s between calls to be safe
REQUEST_DELAY = 2.2


# ─────────────────────────────────────────────────────────────────────────────
def load_sample(dataset_path: str, n_safe: int, n_phishing: int, seed: int = 42) -> list[dict]:
    """Load a stratified random sample from a CSV with 'text_combined' and 'label' columns."""
    safe_pool, phishing_pool = [], []

    print(f"Loading dataset: {dataset_path}")
    with open(dataset_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            label = row.get("label", "").strip()
            text = row.get("text_combined", "").strip()
            if not text:
                continue
            if label == "0":
                safe_pool.append(text)
            elif label == "1":
                phishing_pool.append(text)

    rng = random.Random(seed)
    safe_sample = rng.sample(safe_pool, min(n_safe, len(safe_pool)))
    phishing_sample = rng.sample(phishing_pool, min(n_phishing, len(phishing_pool)))

    records = (
        [{"text": t, "true_label": 0} for t in safe_sample]
        + [{"text": t, "true_label": 1} for t in phishing_sample]
    )
    rng.shuffle(records)
    print(f"  Sampled {len(safe_sample)} safe + {len(phishing_sample)} phishing = {len(records)} total\n")
    return records


# ─────────────────────────────────────────────────────────────────────────────
def verdict_to_binary(verdict: str) -> int:
    """Conservative mapping: Suspicious counts as Phishing (1)."""
    return 0 if verdict == "Safe" else 1


def run_evaluation(records: list[dict]) -> list[dict]:
    """Call analyse_email on every record, with rate-limit delay."""
    results = []
    total = len(records)

    for i, rec in enumerate(records, 1):
        true_label = rec["true_label"]
        text = rec["text"]

        print(f"[{i:>3}/{total}] true={'Safe' if true_label == 0 else 'Phishing'}", end="  →  ", flush=True)

        try:
            output = analyse_email(text)

            if "error" in output:
                verdict = "ERROR"
                confidence = "N/A"
                pred_binary = -1
                reasoning = output.get("error", "")
            else:
                verdict = output.get("verdict", "Unknown")
                confidence = output.get("confidence", "Unknown")
                pred_binary = verdict_to_binary(verdict)
                reasoning = output.get("reasoning", "")

        except Exception as exc:
            verdict = "ERROR"
            confidence = "N/A"
            pred_binary = -1
            reasoning = str(exc)

        correct = "✓" if pred_binary == true_label else "✗"
        print(f"predicted={verdict:<12} {correct}")

        results.append({
            "index": i,
            "true_label": true_label,
            "true_label_str": "Safe" if true_label == 0 else "Phishing",
            "verdict": verdict,
            "pred_binary": pred_binary,
            "confidence": confidence,
            "reasoning": reasoning[:200],
            "correct": pred_binary == true_label,
        })

        # Rate-limit guard (skip delay on last item)
        if i < total:
            time.sleep(REQUEST_DELAY)

    return results


# ─────────────────────────────────────────────────────────────────────────────
def compute_metrics(results: list[dict]) -> dict:
    """Compute binary classification metrics (excluding ERROR predictions)."""
    valid = [r for r in results if r["pred_binary"] in (0, 1)]
    errors = len(results) - len(valid)

    # Confusion matrix values
    tp = sum(1 for r in valid if r["true_label"] == 1 and r["pred_binary"] == 1)
    tn = sum(1 for r in valid if r["true_label"] == 0 and r["pred_binary"] == 0)
    fp = sum(1 for r in valid if r["true_label"] == 0 and r["pred_binary"] == 1)
    fn = sum(1 for r in valid if r["true_label"] == 1 and r["pred_binary"] == 0)

    n = len(valid)
    accuracy   = (tp + tn) / n if n else 0
    precision  = tp / (tp + fp) if (tp + fp) else 0
    recall     = tp / (tp + fn) if (tp + fn) else 0
    f1         = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    specificity = tn / (tn + fp) if (tn + fp) else 0  # true-negative rate

    # Verdict distribution
    verdict_dist = Counter(r["verdict"] for r in results)

    # Confidence distribution
    conf_dist = Counter(r["confidence"] for r in valid)

    # Per-class accuracy
    safe_total    = sum(1 for r in valid if r["true_label"] == 0)
    phish_total   = sum(1 for r in valid if r["true_label"] == 1)
    safe_correct  = tn
    phish_correct = tp

    return {
        "total_evaluated": len(results),
        "valid_predictions": n,
        "errors": errors,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "accuracy":    round(accuracy, 4),
        "precision":   round(precision, 4),
        "recall":      round(recall, 4),
        "f1_score":    round(f1, 4),
        "specificity": round(specificity, 4),
        "per_class": {
            "safe":    {"total": safe_total,  "correct": safe_correct,  "accuracy": round(safe_correct  / safe_total,  4) if safe_total  else 0},
            "phishing": {"total": phish_total, "correct": phish_correct, "accuracy": round(phish_correct / phish_total, 4) if phish_total else 0},
        },
        "verdict_distribution": dict(verdict_dist),
        "confidence_distribution": dict(conf_dist),
    }


# ─────────────────────────────────────────────────────────────────────────────
def print_report(metrics: dict):
    cm = metrics["confusion_matrix"]
    tp, tn, fp, fn = cm["TP"], cm["TN"], cm["FP"], cm["FN"]

    bar = "=" * 52

    print(f"\n{bar}")
    print("  EVALUATION REPORT — PHISHING DETECTION AGENT")
    print(bar)
    print(f"  Total evaluated   : {metrics['total_evaluated']}")
    print(f"  Valid predictions : {metrics['valid_predictions']}")
    print(f"  API errors        : {metrics['errors']}")

    print(f"\n  {'METRIC':<18} {'VALUE':>8}")
    print(f"  {'-'*28}")
    print(f"  {'Accuracy':<18} {metrics['accuracy']:>8.2%}")
    print(f"  {'Precision':<18} {metrics['precision']:>8.2%}")
    print(f"  {'Recall':<18} {metrics['recall']:>8.2%}")
    print(f"  {'F1 Score':<18} {metrics['f1_score']:>8.2%}")
    print(f"  {'Specificity':<18} {metrics['specificity']:>8.2%}")

    print(f"\n  CONFUSION MATRIX  (positive = Phishing/Suspicious)")
    print(f"  {'':20} Predicted Safe  Predicted Phishing")
    print(f"  {'Actual Safe':20} {tn:>14}  {fp:>18}")
    print(f"  {'Actual Phishing':20} {fn:>14}  {tp:>18}")

    print(f"\n  PER-CLASS ACCURACY")
    for cls, data in metrics["per_class"].items():
        print(f"  {cls.capitalize():<18} {data['correct']}/{data['total']} = {data['accuracy']:.2%}")

    print(f"\n  VERDICT DISTRIBUTION")
    for v, c in sorted(metrics["verdict_distribution"].items()):
        print(f"  {v:<18} {c}")

    print(f"\n  CONFIDENCE DISTRIBUTION")
    for v, c in sorted(metrics["confidence_distribution"].items()):
        print(f"  {v:<18} {c}")

    print(bar)
    print(f"  Full results → evaluate_results.csv")
    print(f"  Metrics JSON → evaluate_metrics.json")
    print(bar + "\n")


# ─────────────────────────────────────────────────────────────────────────────
def save_results(results: list[dict], metrics: dict):
    # CSV
    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as fh:
        fieldnames = ["index", "true_label_str", "verdict", "pred_binary",
                      "correct", "confidence", "reasoning"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    # JSON
    with open(METRICS_JSON, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Evaluate phishing detection agent")
    parser.add_argument("--samples", type=int, default=100,
                        help="Total number of emails to test (split evenly safe/phishing)")
    parser.add_argument("--dataset", type=str, default=DATASET_DEFAULT,
                        help="Path to CSV dataset")
    args = parser.parse_args()

    half = args.samples // 2
    records = load_sample(args.dataset, n_safe=half, n_phishing=args.samples - half)

    est_minutes = (len(records) * REQUEST_DELAY) / 60
    print(f"Estimated time: ~{est_minutes:.1f} minutes (rate-limited to ~{60/REQUEST_DELAY:.0f} req/min)\n")

    results = run_evaluation(records)
    metrics = compute_metrics(results)

    print_report(metrics)
    save_results(results, metrics)


if __name__ == "__main__":
    main()
