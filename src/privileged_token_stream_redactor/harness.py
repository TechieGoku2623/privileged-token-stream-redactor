"""Deterministic latency harness for the token redactor."""

from __future__ import annotations

import asyncio
import math
import random
import statistics
import sys
import tracemalloc
from time import perf_counter_ns

from .engine import PrivilegedTokenStreamRedactor
from .exceptions import EngineKernelException
from .wire import FNV64_OFFSET

SEED = 20261002
ITERATIONS = 5000


def _p99(samples: list[float]) -> float:
    ordered = sorted(samples)
    count = len(ordered)
    index = math.ceil(0.99 * count) - 1
    if index < 0:
        return ordered[0]
    if index >= count:
        return ordered[-1]
    return ordered[index]


def _edge_overlong_chunk() -> bool:
    async def _run() -> None:
        engine = PrivilegedTokenStreamRedactor(max_chunk=64)
        try:
            await engine.run(["y" * 65])
        except EngineKernelException as exc:
            if "max" not in str(exc):
                raise AssertionError("overlong fault was mislabeled") from exc
        else:
            raise AssertionError("overlong chunk was accepted")
        viewed = await engine.run(["plain text"])
        if viewed["chunks"] != 1 or viewed["redactions"] != 0:
            raise AssertionError("rejected chunk mutated the stream")
        if viewed["redacted"] != "plain text":
            raise AssertionError("plain chunk was rewritten")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"edge_overlong_chunk failed: {exc}", file=sys.stderr)
        return False
    return True


def _edge_split_marker() -> bool:
    async def _run() -> None:
        engine = PrivilegedTokenStreamRedactor()
        result = await engine.run(
            [
                "distribution copy ATTORNEY-CLIENT ",
                "PRIVILEGED for counsel only",
            ]
        )
        if int(result["split_repairs"]) < 1:
            raise AssertionError("split banner was not repaired")
        redacted = str(result["redacted"])
        expected = "distribution copy [PRIVILEGED] for counsel only"
        if redacted != expected:
            raise AssertionError("split banner was not fully redacted")
        if result["audit_fnv"] == FNV64_OFFSET:
            raise AssertionError("audit chain did not move")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"edge_split_marker failed: {exc}", file=sys.stderr)
        return False
    return True


def _benchmark() -> tuple[int, float, float, int]:
    engine = PrivilegedTokenStreamRedactor()
    rng = random.Random(SEED)
    samples: list[float] = []

    async def _run() -> None:
        for _ in range(ITERATIONS):
            chunk = "hold file " + format(rng.randrange(10000), "04d") + " note"
            started = perf_counter_ns()
            await engine.run([chunk])
            samples.append((perf_counter_ns() - started) / 1000.0)

    tracemalloc.start()
    try:
        asyncio.run(_run())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    average = float(statistics.fmean(samples))
    return len(samples), average, _p99(samples), peak


def main() -> int:
    """Print the harness status dict and return 0 only on success."""
    failures = 0
    if not _edge_overlong_chunk():
        failures += 1
    if not _edge_split_marker():
        failures += 1
    iterations = 0
    average = 0.0
    p99 = 0.0
    peak = 0
    try:
        iterations, average, p99, peak = _benchmark()
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        failures += 1
    else:
        if iterations < ITERATIONS or peak <= 0:
            failures += 1
    status = "ok" if failures == 0 else "fail"
    print(
        {
            "status": status,
            "failures": failures,
            "latency_us": round(average, 3),
            "memory_peak_bytes": peak,
            "benchmark_iterations": iterations,
            "benchmark_avg_us": round(average, 3),
            "benchmark_p99_us": round(p99, 3),
        }
    )
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
