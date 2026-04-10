#!/usr/bin/env python3

import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUDGET_PATH = ROOT / "bench" / "budgets.json"
BENCH_LINE = re.compile(
    r"^(Benchmark\S+)-\d+\s+\d+\s+(\d+(?:\.\d+)?) ns/op\s+(\d+(?:\.\d+)?) B/op\s+(\d+(?:\.\d+)?) allocs/op$"
)


def load_budgets():
    with BUDGET_PATH.open() as f:
        return json.load(f)


def run_benchmarks(command):
    result = subprocess.run(
        command,
        cwd=ROOT,
        shell=True,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def parse_metrics(output):
    metrics = {}
    current_pkg = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("pkg: "):
            current_pkg = line.removeprefix("pkg: ").strip()
            metrics.setdefault(current_pkg, {})
            continue
        match = BENCH_LINE.match(line)
        if not match or current_pkg is None:
            continue
        metrics[current_pkg][match.group(1)] = {
            "ns_op": float(match.group(2)),
            "b_op": float(match.group(3)),
            "allocs_op": float(match.group(4)),
        }
    return metrics


def main():
    budgets = load_budgets()
    output = run_benchmarks(budgets["command"])
    metrics = parse_metrics(output)

    failures = []
    for pkg, bench_budgets in budgets["benchmarks"].items():
        if pkg not in metrics:
            failures.append(f"missing benchmark package output for {pkg}")
            continue
        for bench_name, limit in bench_budgets.items():
            if bench_name not in metrics[pkg]:
                failures.append(f"missing benchmark output for {pkg} {bench_name}")
                continue
            actual = metrics[pkg][bench_name]
            checks = [
                ("ns/op", actual["ns_op"], limit["max_ns_op"]),
                ("B/op", actual["b_op"], limit["max_b_op"]),
                ("allocs/op", actual["allocs_op"], limit["max_allocs_op"]),
            ]
            for label, got, max_value in checks:
                if got > max_value:
                    failures.append(
                        f"{pkg} {bench_name} exceeded {label}: got {got:.2f}, budget {max_value}"
                    )

    sys.stdout.write(output)
    if failures:
        sys.stderr.write("\nBenchmark budget failures:\n")
        for failure in failures:
            sys.stderr.write(f"- {failure}\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
