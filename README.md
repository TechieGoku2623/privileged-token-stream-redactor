# Privileged Token Stream Redactor

A high-throughput, low-latency asynchronous engine engineered to resolve privilege banners, email addresses, SSN-like patterns, and account identifiers inside a chunked text stream, including markers split across chunk boundaries, without writing the raw match into the audit log.

## 🏗️ Systems Architecture & Event Topology

`PrivilegedTokenRedactor` is a single consumer of text the caller already holds. `push_chunk` appends one chunk. `flush` finishes a stream. `redact_stream` is the coroutine that pushes a sequence and returns the redacted text. `audit_tuples` returns the packed 8-byte records. `carry_length` reports how much unmatched tail is still held for a marker that may complete in the next chunk.

Each redaction becomes a stable token (`[PRIVILEGED]` or `[ID]`) plus an audit record of class, offset, and length. The raw match is not an argument to the logger. A TimescaleDB hypertable would store the audit bytes in a deployment; here they stay in a list so a legal hold can count them without a database connection. An `asyncio.Lock` covers the buffer and the audit list. `logging.basicConfig` timestamps every line. An over-long chunk raises `EngineKernelException` and is not retained.

This process redacts text it was given. It is not a tool for collecting documents.

## 📊 Core Visual Walkthrough & Engine Pipeline Flow

```
chunk N                         chunk N+1
   |                               |
   v                               v
push_chunk ---- overlap tail held across the boundary
   |
   v
scan privilege banner / email / SSN-like / account pattern
   |
   +-- match ---- replace with token, append 8-byte audit
   |              log class, offset, length only
   |
   +-- chunk longer than the limit --> EngineKernelException
   |
   v
redacted text + audit_tuples()
```

Insert the structural terminal walkthrough recording at docs/assets/terminal-walkthrough.gif before publishing the release notes.

## ⚡ Low-Level OS Mechanics & Network Physics

The overlap tail is a bounded string, not a reread of the whole stream. A banner that begins in the last bytes of chunk N and ends in chunk N+1 is matched once, at the joined boundary, and the tail length shrinks by the consumed bytes. The scanner does not re-read earlier chunks, so the cost stays proportional to the new chunk plus the fixed overlap.

Audit records are `struct` packed to 8 bytes: class, offset, length. `statistics` summarizes redaction density for the scenario report. `math` guards the density division when the stream is empty. The lock is held across the scan of one chunk so `audit_tuples` cannot observe a half-appended record. No socket is opened. The caller is the network boundary.

## ⚖️ Architecture Trade-offs & Pragmatic Decisions

A general NER model would catch paraphrased privilege language and would also require a weight file, a GPU, and a review of false positives before a legal hold could trust the count. The redactor uses explicit patterns: a privilege banner, an email shape, an SSN-like digit shape, and an account-number shape. The patterns are the contract the harness asserts, including a banner planted across the overlap.

Tokens are stable strings, not a hash of the matched text. A hash would still be a lookup key for the raw value. The audit record stores where and how long, which is enough to prove a redaction happened and not enough to reconstruct the identifier from the log line.

## 🚀 Local Installation & Benchmarking

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python src/main.py
python src/test_harness.py
```

```python
import asyncio

from src.main import PrivilegedTokenRedactor


async def demo() -> None:
    redactor = PrivilegedTokenRedactor()
    await redactor.redact_stream(["counsel review for the matter"])
    await redactor.audit_tuples()


asyncio.run(demo())
```

Runtime dependencies are the Python 3.12 standard library, including `re`. `pip install -r requirements.txt` succeeds with nothing to fetch.

## 🖥️ Terminal Diagnostic Output Preview

```
INFO legal.privilege.redactor redacted class=1 offset=160 length=26
INFO legal.privilege.redactor redacted class=2 offset=213 length=25
INFO legal.privilege.redactor redacted class=4 offset=253 length=27
INFO legal.privilege.redactor redacted class=3 offset=306 length=11
INFO legal.privilege.redactor scenario complete audit_count=4
```

`python src/main.py` exits 0. Stdout reports `overlong_rejected` true and the token strings. The log lines do not contain the matched text.

## 📊 Empirical Benchmarking Performance Report

Measured by `python src/test_harness.py` with a deterministic seed, 5000 iterations, `time.perf_counter_ns` latency in microseconds, and `tracemalloc` peak.

| Metric | Measured |
| --- | ---: |
| Status | PASS |
| Iterations | 5000 |
| Average latency | 57.16 µs |
| Empirical P99 | 73.84 µs |
| tracemalloc peak | 178367 bytes |
| Edge: marker split across chunks | PASS |
| Edge: over-long chunk | PASS |

## 🛡️ Edge-Case Resilience & SOC2/Regulatory Compliance

A privilege banner split across the overlap tail is removed from the redacted text and produces one audit record. An over-long chunk raises `EngineKernelException`, is not retained, and does not append an audit row. Identifier-shaped matches are tokenized. The logging call records class, offset, and length. The harness asserts the raw match is absent from log records.

The control alignment is SOC 2 confidentiality and processing integrity, plus a legal-hold count of redactions. The module does not retain the source document, does not discover new documents, and does not export the pre-redaction buffer. Callers who are under a hold should persist `audit_tuples` in their own store.
