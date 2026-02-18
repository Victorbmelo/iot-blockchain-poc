#!/usr/bin/env python3
"""
collect_metrics.py - Read experiment results and produce Chapter 5 tables.

Usage:
    python scripts/collect_metrics.py
    python scripts/collect_metrics.py --results-dir results
"""
import csv, json, sys
from pathlib import Path

def main():
    results_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    rows = []
    for f in sorted(results_dir.glob("*/metrics.csv")):
        with open(f) as fh:
            rows.extend(csv.DictReader(fh))

    if not rows:
        print("No metrics found. Run 'make exp-all' first.")
        return

    print(f"\n{'Exp':<4} {'Name':<32} {'TPS':>7} {'p50ms':>7} {'p95ms':>7} {'p99ms':>7} {'Err%':>6} {'OK?'}")
    print("-" * 78)
    for r in rows:
        print(f"{r.get('experiment_id','?'):<4} {r.get('experiment_name','?'):<32} "
              f"{float(r.get('throughput_eps',0)):>7.3f} "
              f"{float(r.get('latency_p50_ms',0)):>7.1f} "
              f"{float(r.get('latency_p95_ms',0)):>7.1f} "
              f"{float(r.get('latency_p99_ms',0)):>7.1f} "
              f"{float(r.get('error_rate_pct',0)):>5.1f}% "
              f"{'[OK]' if r.get('criteria_met','False')=='True' else '[FAIL]'}")

    # Write combined CSV for LaTeX table
    out = results_dir / "chapter5_table.csv"
    if rows:
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
        print(f"\nChapter 5 table -> {out}")

if __name__ == "__main__":
    main()
