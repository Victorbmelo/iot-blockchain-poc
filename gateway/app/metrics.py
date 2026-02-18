"""
Metrics collection for the Audit Gateway.

Tracks per-request latency, throughput, and error rate.
Results are exported to a timestamped CSV in the results/ directory.
"""
import csv
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class EventMetric:
    ts: str
    event_id: str
    event_type: str
    severity: int
    zone_id: str
    actor_id: str
    latency_ms: float
    success: bool
    error: Optional[str] = None


@dataclass
class RunSummary:
    run_id: str
    started_at: str
    ended_at: Optional[str]
    total_submitted: int
    total_success: int
    total_failed: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_tps: float


class MetricsCollector:
    """Thread-safe collector for gateway submission metrics."""

    def __init__(self, results_dir: str = "results"):
        self._lock = threading.Lock()
        self._records: list[EventMetric] = []
        self._started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._run_id = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S")
        self._results_dir = Path(results_dir) / self._run_id
        self._results_dir.mkdir(parents=True, exist_ok=True)

    def record(self, metric: EventMetric):
        with self._lock:
            self._records.append(metric)

    def summary(self) -> RunSummary:
        with self._lock:
            records = list(self._records)

        if not records:
            return RunSummary(
                run_id=self._run_id,
                started_at=self._started_at,
                ended_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                total_submitted=0,
                total_success=0,
                total_failed=0,
                avg_latency_ms=0.0,
                p95_latency_ms=0.0,
                p99_latency_ms=0.0,
                throughput_tps=0.0,
            )

        latencies = sorted(r.latency_ms for r in records if r.success)
        success_count = sum(1 for r in records if r.success)
        failed_count = len(records) - success_count

        avg = sum(latencies) / len(latencies) if latencies else 0.0
        p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
        p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0

        # Throughput: total successful submissions over wall-clock duration
        started = datetime.fromisoformat(self._started_at)
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        tps = success_count / elapsed if elapsed > 0 else 0.0

        return RunSummary(
            run_id=self._run_id,
            started_at=self._started_at,
            ended_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            total_submitted=len(records),
            total_success=success_count,
            total_failed=failed_count,
            avg_latency_ms=round(avg, 2),
            p95_latency_ms=round(p95, 2),
            p99_latency_ms=round(p99, 2),
            throughput_tps=round(tps, 4),
        )

    def export(self):
        """Write events.csv and metrics.csv to the run directory."""
        with self._lock:
            records = list(self._records)

        # events.csv
        events_path = self._results_dir / "events.csv"
        if records:
            with open(events_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=asdict(records[0]).keys())
                writer.writeheader()
                for r in records:
                    writer.writerow(asdict(r))

        # metrics.csv (single-row summary)
        summary = self.summary()
        metrics_path = self._results_dir / "metrics.csv"
        with open(metrics_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=asdict(summary).keys())
            writer.writeheader()
            writer.writerow(asdict(summary))

        return str(self._results_dir)

    def recent(self, n: int = 50) -> list[EventMetric]:
        with self._lock:
            return list(self._records[-n:])

    @property
    def run_id(self) -> str:
        return self._run_id


# Module-level singleton - shared across the gateway process.
collector = MetricsCollector(results_dir=os.getenv("RESULTS_DIR", "results"))
