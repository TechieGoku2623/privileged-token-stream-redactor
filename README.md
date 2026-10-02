# Privileged Token Stream Redactor

A high-throughput, low-latency asynchronous engine engineered to resolve privilege banners and direct identifiers in a caller-held text stream by redacting markers that split across chunks and sealing each redaction into an FNV-1a audit chain.

Website: https://github.com/TechieGoku2623/privileged-token-stream-redactor

Topics: `python` `asyncio` `legaltech` `redaction` `privacy` `compliance`


## 🏗️ Systems Architecture & Event Topology

`PrivilegedTokenStreamRedactor` accepts the chunks the caller already holds. `run(records)` appends each chunk under an `asyncio.Lock`, keeps an overlap tail, redacts the committable prefix, and flushes the tail at the end of the batch. The returned dict is JSON-serializable: `redactions`, `audit_fnv`, `chunks`, `split_repairs`, and `redacted`.

Detection uses the `re` module:

| Class code | Marker | Replacement |
| --- | --- | --- |
| 1 | attorney-client and work-product banners | `[PRIVILEGED]` |
| 2 | email addresses | `[ID]` |
| 3 | SSN-like `\d{3}-\d{2}-\d{4}` | `[ID]` |
| 4 | labeled or long account numbers | `[ID]` |

Each redaction appends an 8-byte audit record, `struct` format `<IHH`: stream offset, original length, and class code. Those bytes are folded into a running 64-bit FNV-1a chain (`audit_fnv`) so a legal hold can detect a tampered trail. The raw match is never written to the log. A chunk longer than the configured maximum (default 65536) raises `EngineKernelException` and does not advance the chunk counter.

## 📊 Core Visual Walkthrough & Engine Pipeline Flow

Engine run.

![Engine run](docs/assets/terminal-walkthrough.gif)

Benchmark harness.

![Benchmark harness](docs/assets/benchmark-walkthrough.gif)

Unit tests.

![Unit tests](docs/assets/tests-walkthrough.gif)

```
chunk stream the caller already holds
        |
        v
length gate ---- longer than max_chunk --> EngineKernelException
        |
        v
append to the carry buffer
record the chunk boundary
        |
        v
commit the prefix ahead of the overlap tail
pull the cut back when a match straddles it
        |
        +--> banner --> [PRIVILEGED]
        +--> email, SSN, account --> [ID]
        |
        v
pack (offset, length, class) and fold FNV-1a
count a split when a boundary sits inside the match
        |
        v
flush the tail
{redactions, audit_fnv, chunks, split_repairs, redacted}
```

Insert the structural terminal walkthrough recording at docs/assets/terminal-walkthrough.gif before publishing the release notes.

## ⚡ Low-Level OS Mechanics & Network Physics

The overlap tail defaults to 256 characters. While the buffer is shorter than that tail, nothing is emitted, so a banner that begins in one chunk and ends in the next is still one match. On flush, the whole remainder is redacted. A boundary offset is stored where each new chunk starts. If a match has `start < boundary < end`, `split_repairs` increments once for that match.

Overlapping candidates are resolved by earliest start, then by class priority, then by longer span. The replacement is written into the emitted text only. The scanner does not run again on `[PRIVILEGED]` or `[ID]`.

FNV-1a 64 starts at the offset basis `14695981039346656037`. For each audit byte `b`:

```
state = state XOR b
state = (state * 1099511628211) mod 2^64
```

The same input therefore yields the same `audit_fnv`. Flipping any audit byte moves the chain. `statistics.fmean` and `statistics.pstdev` summarize redaction spans, and `math.fsum` builds the density logged with the batch. `struct.calcsize` checks the audit record before it is hashed.

## ⚖️ Architecture Trade-offs & Pragmatic Decisions

A single-shot redact of the joined string would miss the operational constraint that chunks arrive separately and that a marker can be cut between them. The overlap tail pays a bounded hold, default 256 characters, so typical banners, emails, and account tokens survive the cut. A marker whose incomplete prefix is longer than the overlap can still be split; raise `overlap` when the corpus has longer tokens.

The audit record stores offset, length, and class code. It does not store the matched text. That keeps the legal-hold trail useful for counting and tamper evidence while keeping the identifier out of the log and out of the hash input's human-readable form. The hash covers the packed record, so a change to offset, length, or class is visible.

Class priority lets a labeled account consume its digits once. A bare 12-to-17 digit run still maps to class 4 when no earlier label covers it.

## 🚀 Local Installation & Benchmarking

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
python -m privileged_token_stream_redactor
python -m privileged_token_stream_redactor.harness
```

```python
import asyncio

from privileged_token_stream_redactor import PrivilegedTokenStreamRedactor


async def demo() -> None:
    engine = PrivilegedTokenStreamRedactor()
    result = await engine.run(
        [
            "ATTORNEY-CLIENT ",
            "PRIVILEGED memo for reviewer@example.com",
        ]
    )
    print(result["redactions"], result["split_repairs"])


asyncio.run(demo())
```

The runtime is the Python 3.12 standard library. `pip install -r requirements.txt` succeeds with comments only. Install the package with `pip install .`.

## 🖥️ Terminal Diagnostic Output Preview

```
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redacted class=1 offset=17 length=26
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redacted class=2 offset=89 length=20
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redacted class=3 offset=126 length=11
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redacted class=4 offset=154 length=27
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redacted class=1 offset=198 length=12
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] redaction density=0.395062 mean_span=19.200 spread=6.735 chunks=6
2026-10-02T02:54:16+0000 INFO [legal.privilege.redactor] scenario complete redactions=5 chunks=6 split_repairs=1
{'redactions': 5, 'audit_fnv': 13840402294878474496, 'chunks': 6, 'split_repairs': 1, 'redacted': 'Hold memorandum. [PRIVILEGED] and prepared for counsel. Route questions to [ID]. The file cites [ID] under the hold. [ID] remains sealed. [PRIVILEGED] draft stays with the review set.'}
```

`python -m privileged_token_stream_redactor` exits 0. The log lines carry class, offset, and length. They do not carry the matched text.

## 📊 Empirical Benchmarking Performance Report

Measured by `python -m privileged_token_stream_redactor.harness` with seed `20261002`, 5000 iterations, `perf_counter_ns` latency in microseconds, and `tracemalloc` peak. The harness prints this status dict and exits 0 only when every edge passes:

```
{'status': 'ok', 'failures': 0, 'latency_us': 32.151, 'memory_peak_bytes': 175221, 'benchmark_iterations': 5000, 'benchmark_avg_us': 32.151, 'benchmark_p99_us': 49.033}
```

| Metric | Measured |
| --- | ---: |
| Status | ok |
| Failures | 0 |
| Iterations | 5000 |
| Average latency | 32.151 µs |
| Empirical P99 | 49.033 µs |
| tracemalloc peak | 175221 bytes |
| Edge: overlong chunk | pass |
| Edge: split banner | pass |

## 🛡️ Edge-Case Resilience & SOC2/Regulatory Compliance

A chunk longer than `max_chunk` raises `EngineKernelException`. The following plain chunk is emitted unchanged, `redactions` stays 0, and `audit_fnv` stays at the FNV offset basis.

A banner split as `ATTORNEY-CLIENT ` and `PRIVILEGED` is one match. `split_repairs` is at least 1, and the emitted text is `distribution copy [PRIVILEGED] for counsel only`. The audit chain moves.

This module redacts text the caller already holds. It supports a SOC 2 confidentiality and processing-integrity control and a legal-hold count of redactions. It does not collect text from another system. The audit row is `(offset, length, class_code)` and the log stays free of the raw match.
