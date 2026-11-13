from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .evaluation import bootstrap_ci, label_distribution, mcnemar_exact, metrics
from .io import load_data
from .methods import Method, Prediction, api_method, rule_predict, train_gradient_method


def _load_local_env() -> None:
    """Load repository-local environment variables for direct experiment runs."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _raw_run(path: Path, method: Method, pair, prediction: Prediction, latency_ms: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "pair_id": pair.pair_id,
        "method": method.name,
        "input": {"pair_id": pair.pair_id, "finding_a": pair.finding_a, "finding_b": pair.finding_b},
        "output": prediction.raw_output if prediction.raw_output is not None else {
            "label": prediction.label,
            "confidence": prediction.confidence,
            "rationale": prediction.rationale,
        },
        "latency_ms": latency_ms,
        "model_version": prediction.model_version or method.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def run(config_path: str | Path) -> int:
    _load_local_env()
    config_file = Path(config_path)
    config = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    llm_config = config.setdefault("llm", {})
    jev_config = config.setdefault("jev", {})
    if not llm_config.get("endpoint"):
        llm_config["endpoint"] = os.environ.get(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        ).rstrip("/") + "/chat/completions"
    if not llm_config.get("model") and llm_config.get("endpoint"):
        llm_config["model"] = os.environ.get("OPENROUTER_MODEL", "")
    llm_config.setdefault("api_key_env", "GENERAL_LLM_API_KEY")
    jev_config.setdefault("api_key_env", "JEV_API_KEY")
    findings_path = Path(config["findings_path"])
    pairs_path = Path(config["pairs_path"])
    if not findings_path.is_absolute():
        findings_path = config_file.parent.parent / findings_path if config_file.parent.name == "experiments" else findings_path
    if not pairs_path.is_absolute():
        pairs_path = config_file.parent.parent / pairs_path if config_file.parent.name == "experiments" else pairs_path
    data = load_data(findings_path, pairs_path)
    output_dir = Path(config.get("results_dir", "experiments/results"))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "validation.json").write_text(json.dumps({
        "valid": not data.errors,
        "errors": data.errors,
        "warnings": data.warnings,
        "provenance": "REAL" if not data.warnings else "SYNTHETIC_OR_MIXED",
    }, indent=2), encoding="utf-8")
    if data.errors:
        print("Validation failed; no methods were run.", file=sys.stderr)
        for error in data.errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    seed = int(config.get("random_seed", 0))
    bootstrap_count = int(config.get("bootstrap_resamples", 1000))
    train_pairs = [pair for pair in data.pairs if pair.split == "train"]
    test_pairs = [pair for pair in data.pairs if pair.split == "test"]
    try:
        gradient_method = train_gradient_method(train_pairs, data.findings, seed)
        gradient_reason = None
    except (ValueError, RuntimeError) as exc:
        gradient_method = None
        gradient_reason = f"training failed: {exc}"
    methods: list[tuple[str, Method | None, str | None]] = [
        ("M1 Rule-based", Method("M1 Rule-based", "rules-v1", lambda pair: rule_predict(pair, data.findings)), None),
        ("M2 Gradient-boosted classifier", gradient_method, gradient_reason),
    ]
    llm = config.get("llm", {})
    methods.append(("M3 General LLM", *api_method(
        "M3 General LLM", llm.get("endpoint", ""), llm.get("model", ""),
        llm.get("api_key_env", "GENERAL_LLM_API_KEY"), data.findings,
    )))
    jev = config.get("jev", {})
    methods.append(("M4 TypeSafe Jev", *api_method(
        "M4 TypeSafe Jev", jev.get("endpoint", ""), jev.get("model", ""),
        jev.get("api_key_env", "JEV_API_KEY"), data.findings,
    )))

    run_dir = output_dir / "raw_runs"
    records: list[dict[str, object]] = []
    metrics_output: dict[str, object] = {
        "provenance": "REAL" if not data.warnings else "SYNTHETIC_OR_MIXED",
        "test_pairs": len(test_pairs),
        "label_distribution": label_distribution([pair.label for pair in test_pairs]),
        "warnings": [
            f"class {label} has fewer than 5 test examples"
            for label, count in label_distribution([pair.label for pair in test_pairs]).items()
            if count < 5
        ],
        "methods": {},
        "comparisons_vs_m1": {},
    }
    predictions: dict[str, list[str]] = {}
    for name, method, reason in methods:
        if method is None:
            metrics_output["methods"][name] = {"status": "NOT RUN", "reason": reason}
            continue
        predictions[name] = []
        latencies: list[float] = []
        token_counts: list[int] = []
        errors: list[dict[str, object]] = []
        for pair in test_pairs:
            started = time.perf_counter()
            try:
                prediction = method.predict(pair)
            except (RuntimeError, ValueError, KeyError) as exc:
                metrics_output["methods"][name] = {"status": "NOT RUN", "reason": str(exc)}
                predictions.pop(name, None)
                break
            latency_ms = (time.perf_counter() - started) * 1000
            predictions[name].append(prediction.label)
            latencies.append(latency_ms)
            if prediction.token_count is not None:
                token_counts.append(prediction.token_count)
            _raw_run(run_dir / f"{name.split()[0].lower()}.jsonl", method, pair, prediction, latency_ms)
            if prediction.label != pair.label:
                errors.append({
                    "pair_id": pair.pair_id,
                    "expected": pair.label,
                    "predicted": prediction.label,
                    "finding_a": data.findings[pair.finding_a].description,
                    "finding_b": data.findings[pair.finding_b].description,
                })
            records.append({
                "pair_id": pair.pair_id, "method": name, "expected": pair.label,
                "predicted": prediction.label, "confidence": prediction.confidence,
                "latency_ms": round(latency_ms, 3), "token_count": prediction.token_count,
            })
        if name not in predictions:
            continue
        base_metrics = metrics([pair.label for pair in test_pairs], predictions[name])
        ci = {
            metric: bootstrap_ci([pair.label for pair in test_pairs], predictions[name], metric, bootstrap_count, seed)
            for metric in ("precision_same", "recall_same", "f1_same", "macro_f1")
        }
        metrics_output["methods"][name] = {
            "status": "RUN", "metrics": base_metrics, "confidence_intervals_95": ci,
            "mean_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
            "total_tokens": sum(token_counts) if token_counts else None,
            "total_cost": (
                sum(token_counts) * float(config["cost_per_token"])
                if token_counts and config.get("cost_per_token") is not None else None
            ),
            "errors": errors,
        }
    if "M1 Rule-based" in predictions:
        for name, predicted in predictions.items():
            if name == "M1 Rule-based":
                continue
            metrics_output["comparisons_vs_m1"][name] = {
                "test": "exact McNemar test on paired correctness",
                "p_value": mcnemar_exact(
                    [pair.label for pair in test_pairs], predictions["M1 Rule-based"], predicted,
                ),
            }
    (output_dir / "metrics.json").write_text(json.dumps(metrics_output, indent=2), encoding="utf-8")
    with (output_dir / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=records[0].keys() if records else ["pair_id"])
        writer.writeheader()
        writer.writerows(records)
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "bootstrap_resamples": bootstrap_count,
        "config": config,
        "input_hashes": {str(findings_path): _sha256(findings_path), str(pairs_path): _sha256(pairs_path)},
        "method_versions": {name: method.version if method else reason for name, method, reason in methods},
        "provenance": metrics_output["provenance"],
    }
    (output_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the controlled finding-correlation experiment")
    parser.add_argument("--config", default="experiments/config.yaml")
    raise SystemExit(run(parser.parse_args().config))


if __name__ == "__main__":
    main()
