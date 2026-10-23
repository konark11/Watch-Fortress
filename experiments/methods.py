from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .io import Finding, Pair

LABELS = ("SAME", "RELATED", "DIFFERENT")
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ENVIRONMENT_VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DIRECT_KEY_PREFIXES = ("sk-", "apikey_")


@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float | None
    rationale: str | None = None
    raw_output: object | None = None
    model_version: str | None = None
    token_count: int | None = None


@dataclass(frozen=True)
class Method:
    name: str
    version: str
    predict: Callable[[Pair], Prediction]


def _is_service_detection(finding: Finding) -> bool:
    text = f"{finding.scanner} {finding.title} {finding.description}".lower()
    return finding.scanner.lower() in {"nmap", "masscan"} or "service detected" in text


def rule_predict(pair: Pair, findings: dict[str, Finding]) -> Prediction:
    first, second = findings[pair.finding_a], findings[pair.finding_b]
    same_endpoint = first.asset_id == second.asset_id and first.port == second.port
    same_cve = bool(first.cve) and first.cve == second.cve
    if same_endpoint and same_cve:
        return Prediction("SAME", 1.0, "same CVE on the same asset and port")
    if same_endpoint and (_is_service_detection(first) or _is_service_detection(second)):
        return Prediction("RELATED", 1.0, "same asset and port with a service-detection record")
    return Prediction("DIFFERENT", 1.0, "rule conditions did not match")


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def pair_features(pair: Pair, findings: dict[str, Finding]) -> list[float]:
    first, second = findings[pair.finding_a], findings[pair.finding_b]
    left, right = _tokens(first.title), _tokens(second.title)
    union = left | right
    return [
        float(bool(first.cve) and first.cve == second.cve),
        float(first.port == second.port),
        float(first.asset_id == second.asset_id),
        float(first.protocol == second.protocol),
        len(left & right) / len(union) if union else 0.0,
        float(abs(SEVERITY.get(first.severity.lower(), 0) - SEVERITY.get(second.severity.lower(), 0))),
    ]


def train_gradient_method(train_pairs: list[Pair], findings: dict[str, Finding], seed: int) -> Method:
    from sklearn.ensemble import GradientBoostingClassifier

    model = GradientBoostingClassifier(random_state=seed)
    model.fit([pair_features(pair, findings) for pair in train_pairs], [pair.label for pair in train_pairs])

    def predict(pair: Pair) -> Prediction:
        features = [pair_features(pair, findings)]
        label = str(model.predict(features)[0])
        confidence = float(max(model.predict_proba(features)[0]))
        return Prediction(label, confidence, "scikit-learn GradientBoostingClassifier")

    return Method("M2 Gradient-boosted classifier", "scikit-learn GradientBoostingClassifier", predict)


def api_method(
    name: str, endpoint: str, model: str, api_key_env: str,
    findings: dict[str, Finding] | None = None, timeout: float = 30.0,
) -> tuple[Method | None, str | None]:
    key = os.getenv(api_key_env)
    direct_key = (
        not ENVIRONMENT_VARIABLE.fullmatch(api_key_env)
        or len(api_key_env) > 64
        or api_key_env.startswith(DIRECT_KEY_PREFIXES)
    )
    if not key and direct_key:
        key = api_key_env
    if not key:
        return None, f"{api_key_env} is not set"
    if not endpoint or not model:
        return None, "endpoint or model is not configured"

    def predict(pair: Pair) -> Prediction:
        pair_input: object = {"finding_a": pair.finding_a, "finding_b": pair.finding_b}
        if findings is not None:
            pair_input = {
                "finding_a": findings[pair.finding_a].__dict__,
                "finding_b": findings[pair.finding_b].__dict__,
            }
        prompt = (
            "Classify this finding pair as exactly SAME, RELATED, or DIFFERENT. "
            'Return JSON: {"label": "...", "confidence": 0.0, "rationale": "..."}\n'
            f"{json.dumps(pair_input, sort_keys=True)}"
        )
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        request = urllib.request.Request(
            endpoint, data=payload,
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"{name} API request failed: HTTP {exc.code}: {detail[:500]}") from exc
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise RuntimeError(f"{name} API request failed: {exc}") from exc
        output = raw.get("output", raw)
        if isinstance(raw.get("choices"), list) and raw["choices"]:
            message = raw["choices"][0].get("message", {})
            if isinstance(message, dict):
                output = message.get("content", output)
        if isinstance(output, str):
            output = json.loads(output.strip().removeprefix("```json").removesuffix("```").strip())
        label = str(output.get("label", "")).upper()
        if label not in LABELS:
            raise ValueError(f"{name} returned invalid label {label!r}")
        return Prediction(
            label=label,
            confidence=float(output["confidence"]),
            rationale=str(output.get("rationale", "")),
            raw_output=raw,
            model_version=str(raw.get("model_version") or raw.get("model") or model),
            token_count=raw.get("usage", {}).get("total_tokens") if isinstance(raw.get("usage"), dict) else None,
        )

    return Method(name, model, predict), None
