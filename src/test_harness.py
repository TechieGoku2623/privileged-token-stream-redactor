"""Deterministic harness for split markers, over-long chunks, and latency."""

from __future__ import annotations

import asyncio
import logging
import random
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SEED = 20261001
ITERATIONS = 5000


def _percentile_index(count: int) -> int:
    index = (99 * count + 99) // 100 - 1
    if index < 0:
        return 0
    if index >= count:
        return count - 1
    return index


def _edge_split_marker(module: object) -> str:
    engine_cls = module.PrivilegedTokenRedactor

    async def _run() -> None:
        engine = engine_cls()
        filler = "section " * 20
        first_chunk = filler + "ATTORNEY-CLIENT "
        if len(first_chunk) <= engine_cls.HOLD:
            raise AssertionError("fixture does not cross the overlap tail")
        first = await engine.push_chunk(first_chunk)
        if "ATTORNEY-CLIENT" in str(first["emitted"]):
            raise AssertionError("partial banner left the overlap tail")
        second = await engine.push_chunk("PRIVILEGED memorandum for counsel.")
        flushed = await engine.flush()
        combined = (
            str(first["emitted"]) + str(second["emitted"]) + str(flushed["emitted"])
        )
        if "ATTORNEY-CLIENT" in combined:
            raise AssertionError("split privilege banner survived redaction")
        if engine_cls.TOKEN_PRIVILEGED not in combined:
            raise AssertionError("split privilege banner was not tokenized")
        if int(flushed["audit_count"]) < 1:
            raise AssertionError("split banner produced no audit record")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"edge_split_marker failed: {exc}", file=sys.stderr)
        return "FAIL"
    return "PASS"


def _edge_overlong_chunk(module: object) -> str:
    engine_cls = module.PrivilegedTokenRedactor
    error_cls = module.EngineKernelException

    async def _run() -> None:
        engine = engine_cls()
        try:
            await engine.push_chunk("a" * (engine_cls.MAX_CHUNK + 1))
        except error_cls as exc:
            if "chunk length" not in str(exc):
                raise AssertionError("over-long fault was mislabeled") from exc
        else:
            raise AssertionError("over-long chunk was accepted")
        if await engine.carry_length() != 0:
            raise AssertionError("rejected chunk was retained")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"edge_overlong_chunk failed: {exc}", file=sys.stderr)
        return "FAIL"
    return "PASS"


def _identifier_not_logged(module: object) -> str:
    engine_cls = module.PrivilegedTokenRedactor
    email = "reviewer@example.com"
    ssn = "219-09-9999"

    class _Capture(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.messages: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.messages.append(record.getMessage())

    async def _run() -> None:
        handler = _Capture()
        logger = logging.getLogger("legal.privilege.redactor")
        logger.addHandler(handler)
        try:
            engine = engine_cls()
            result = await engine.redact_stream(
                [f"Reach counsel at {email} regarding {ssn} only."]
            )
        finally:
            logger.removeHandler(handler)
        redacted = str(result["redacted"])
        if engine_cls.TOKEN_ID not in redacted:
            raise AssertionError("identifier was not tokenized")
        if email in redacted or ssn in redacted:
            raise AssertionError("identifier remained in the redacted text")
        for message in handler.messages:
            if email in message or ssn in message:
                raise AssertionError("raw identifier reached a log record")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"identifier_not_logged failed: {exc}", file=sys.stderr)
        return "FAIL"
    return "PASS"


def _benchmark(module: object) -> tuple[int, float, float, int]:
    engine_cls = module.PrivilegedTokenRedactor
    rng = random.Random(SEED)
    words = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
    chunks = [" ".join(rng.choice(words) for _ in range(8)) for _ in range(ITERATIONS)]
    engine = engine_cls()

    async def _run() -> list[float]:
        samples: list[float] = []
        for chunk in chunks:
            started = time.perf_counter_ns()
            await engine.push_chunk(chunk)
            elapsed_us = (time.perf_counter_ns() - started) / 1000.0
            samples.append(elapsed_us)
        await engine.flush()
        return samples

    tracemalloc.start()
    try:
        samples = asyncio.run(_run())
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    average = sum(samples) / len(samples)
    ordered = sorted(samples)
    p99 = ordered[_percentile_index(len(ordered))]
    return len(samples), average, p99, peak


def main() -> int:
    import main as engine_module

    status = {
        "edge_split_marker": _edge_split_marker(engine_module),
        "edge_overlong_chunk": _edge_overlong_chunk(engine_module),
        "identifier_not_logged": _identifier_not_logged(engine_module),
        "benchmark": "FAIL",
    }
    try:
        count, average, p99, peak = _benchmark(engine_module)
        print(
            f"BENCH n={count} avg_us={average:.2f} "
            f"p99_us={p99:.2f} peak_bytes={peak}"
        )
        if count >= ITERATIONS and average >= 0.0 and peak > 0:
            status["benchmark"] = "PASS"
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
    print(status)
    if all(value == "PASS" for value in status.values()):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
