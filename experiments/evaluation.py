from __future__ import annotations

import math
import random
from collections import Counter
from typing import Sequence

LABELS = ("SAME", "RELATED", "DIFFERENT")


def _f1(y_true: Sequence[str], y_pred: Sequence[str], positive: str | None = None) -> float:
    classes = (positive,) if positive else LABELS
    scores = []
    for label in classes:
        tp = sum(a == label and b == label for a, b in zip(y_true, y_pred))
        fp = sum(a != label and b == label for a, b in zip(y_true, y_pred))
        fn = sum(a == label and b != label for a, b in zip(y_true, y_pred))
        if tp == 0 and (fp or fn):
            scores.append(0.0)
        elif tp == fp == fn == 0:
            scores.append(0.0)
        else:
            scores.append(2 * tp / (2 * tp + fp + fn))
    return sum(scores) / len(scores)


def metrics(y_true: Sequence[str], y_pred: Sequence[str]) -> dict[str, object]:
    same_true = [label == "SAME" for label in y_true]
    same_pred = [label == "SAME" for label in y_pred]
    tp = sum(a and b for a, b in zip(same_true, same_pred))
    fp = sum(not a and b for a, b in zip(same_true, same_pred))
    fn = sum(a and not b for a, b in zip(same_true, same_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    matrix = {actual: {predicted: sum(a == actual and b == predicted for a, b in zip(y_true, y_pred)) for predicted in LABELS} for actual in LABELS}
    return {
        "precision_same": precision,
        "recall_same": recall,
        "f1_same": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "macro_f1": _f1(y_true, y_pred),
        "confusion_matrix": matrix,
    }


def bootstrap_ci(y_true: Sequence[str], y_pred: Sequence[str], metric: str, resamples: int, seed: int) -> tuple[float, float]:
    rng = random.Random(seed)
    values = []
    indices = range(len(y_true))
    for _ in range(resamples):
        sample = [rng.randrange(len(y_true)) for _ in indices]
        calculated = metrics([y_true[i] for i in sample], [y_pred[i] for i in sample])[metric]
        values.append(float(calculated))
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def mcnemar_exact(y_true: Sequence[str], first: Sequence[str], second: Sequence[str]) -> float:
    b = sum(a == x and a != y for a, x, y in zip(y_true, first, second))
    c = sum(a != x and a == y for a, x, y in zip(y_true, first, second))
    if b + c == 0:
        return 1.0
    tail = min(b, c)
    probability = sum(math.comb(b + c, k) for k in range(tail + 1)) / (2 ** (b + c))
    return min(1.0, 2 * probability)


def label_distribution(labels: Sequence[str]) -> dict[str, int]:
    return dict(Counter(labels))
