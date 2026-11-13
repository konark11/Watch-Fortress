"""Low-cardinality observability primitives.

The application remains usable without an OTLP collector or the optional
Prometheus client.  Span attributes and log fields deliberately contain only
bounded operational metadata; payloads and identifiers are never recorded.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar
from typing import Iterator

try:
    from opentelemetry import trace
    from opentelemetry.propagate import inject, extract
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
except ImportError:  # optional dependency: normal operation needs no collector
    trace = None

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"
    Counter = Gauge = Histogram = None

correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
logger = logging.getLogger("watch_fortress")


def configure() -> None:
    if trace is None or not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return
    provider = TracerProvider(resource=Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "watch-fortress")}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)


def _tracer():
    return trace.get_tracer("watch-fortress") if trace is not None else None


@contextlib.contextmanager
def span(name: str, **attributes) -> Iterator[object]:
    tracer = _tracer()
    if tracer is None:
        yield contextlib.nullcontext()
        return
    safe = {key: value for key, value in attributes.items() if value is not None and key not in {"prompt", "answer", "content", "raw_output", "target"}}
    with tracer.start_as_current_span(name, attributes=safe) as current:
        yield current


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def set_correlation(value: str | None = None) -> str:
    value = value or new_correlation_id()
    correlation_id.set(value[:64])
    return value[:64]


def inject_job_context(payload: dict) -> dict:
    """Return a carrier suitable for durable storage without message content."""
    carrier = {"correlation_id": correlation_id.get() or new_correlation_id()}
    if trace is not None:
        inject(carrier)
    return carrier


def extract_job_context(carrier: dict | None) -> None:
    carrier = carrier or {}
    set_correlation(carrier.get("correlation_id"))
    if trace is not None:
        extract(carrier)


def safe_log(event: str, **fields) -> None:
    allowed = {"correlation_id", "route", "provider", "model", "backend", "latency_ms", "result_count", "job_type", "status", "outcome"}
    record = {key: value for key, value in fields.items() if key in allowed and value is not None}
    record["correlation_id"] = record.get("correlation_id") or correlation_id.get()
    logger.info(json.dumps({"event": event, **record}, separators=(",", ":")))


def redact_url(value: str) -> str:
    return re.sub(r"([?&](?:token|key|api_key|password|secret|authorization)=)[^&]+", r"\1[REDACTED]", value, flags=re.I)


def _metric(factory, name, documentation, labels=()):
    return factory(name, documentation, labels) if factory else None


http_requests = _metric(Counter, "watch_fortress_http_requests_total", "HTTP requests", ("route", "status_class"))
http_errors = _metric(Counter, "watch_fortress_http_errors_total", "HTTP errors", ("route", "status_class"))
http_duration = _metric(Histogram, "watch_fortress_http_request_duration_seconds", "HTTP duration", ("route",))
rag_stage_duration = _metric(Histogram, "watch_fortress_rag_stage_duration_seconds", "RAG stage duration", ("stage",))
rag_latency = _metric(Histogram, "watch_fortress_rag_latency_seconds", "RAG total latency")
retrieval_candidates = _metric(Histogram, "watch_fortress_retrieval_candidates", "Retrieval candidates", ("stage", "backend"))
answer_outcomes = _metric(Counter, "watch_fortress_answer_outcomes_total", "Answer outcomes", ("outcome",))
citations = _metric(Histogram, "watch_fortress_citations", "Citation count")
queue_depth = _metric(Gauge, "watch_fortress_queue_depth", "Queued jobs", ("job_type",))
job_duration = _metric(Histogram, "watch_fortress_job_duration_seconds", "Job duration", ("job_type", "status"))
job_events = _metric(Counter, "watch_fortress_job_events_total", "Job lifecycle events", ("job_type", "event"))
scan_duration = _metric(Histogram, "watch_fortress_scan_duration_seconds", "Scan duration", ("status",))
indexing_duration = _metric(Histogram, "watch_fortress_indexing_duration_seconds", "Index duration")
retention_duration = _metric(Histogram, "watch_fortress_retention_purge_duration_seconds", "Retention duration")


def observe(metric, value, *labels) -> None:
    if metric is None:
        return
    child = metric.labels(*labels) if labels else metric
    child.observe(value)


def increment(metric, *labels) -> None:
    if metric is None:
        return
    child = metric.labels(*labels) if labels else metric
    child.inc()


def metrics_payload() -> tuple[bytes, str]:
    if generate_latest is None:
        return b"# prometheus_client is not installed\n", CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST
