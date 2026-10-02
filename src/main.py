"""Redact privilege banners and direct identifiers from a chunk stream.

The caller already holds the text. This process replaces markers with stable
tokens and keeps an 8-byte audit record per redaction. A TimescaleDB hypertable
would store those records in a deployment; here they stay in a list so a legal
hold can count them without a database connection.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import statistics
import struct
import sys
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    force=True,
)
LOGGER = logging.getLogger("legal.privilege.redactor")


class EngineKernelException(Exception):
    """Raised when a chunk cannot be accepted into the redaction stream."""


class PrivilegedTokenRedactor:
    """Stream redactor with an overlap tail for markers split across chunks."""

    MAX_CHUNK = 65536
    HOLD = 128
    MAX_SPAN = 128
    CLASS_PRIVILEGED = 1
    CLASS_EMAIL = 2
    CLASS_SSN = 3
    CLASS_ACCOUNT = 4
    TOKEN_PRIVILEGED = "[PRIVILEGED]"
    TOKEN_ID = "[ID]"
    AUDIT = struct.Struct("<IHH")
    _PRIVILEGED_RE = re.compile(
        r"(?i)(?:"
        r"attorney[\s\-]*work[\s\-]*product"
        r"|attorney[\s\-]*client[\s\-]+(?:privileged|privilege|communication)"
        r"|privileged[\s\-]+and[\s\-]+confidential"
        r"|work[\s\-]*product"
        r")"
    )
    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    _SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    _ACCOUNT_RE = re.compile(
        r"(?i)\b(?:account|acct)\s*(?:number|no\.?|#)?\s*[:#]?\s*\d{8,17}\b"
    )

    def __init__(self) -> None:
        if self.AUDIT.size != 8:
            raise EngineKernelException("audit record width drifted")
        if self.HOLD < 1 or self.MAX_SPAN < 1:
            raise EngineKernelException("overlap window must be positive")
        self._lock = asyncio.Lock()
        self._buffer = ""
        self._buffer_origin = 0
        self._audit: list[bytes] = []
        self._class_counts: dict[int, int] = {
            self.CLASS_PRIVILEGED: 0,
            self.CLASS_EMAIL: 0,
            self.CLASS_SSN: 0,
            self.CLASS_ACCOUNT: 0,
        }
        self._spans: deque[int] = deque(maxlen=256)
        self._chunk_lengths: deque[int] = deque(maxlen=256)
        self._rules: tuple[tuple[re.Pattern[str], int, str], ...] = (
            (self._PRIVILEGED_RE, self.CLASS_PRIVILEGED, self.TOKEN_PRIVILEGED),
            (self._EMAIL_RE, self.CLASS_EMAIL, self.TOKEN_ID),
            (self._SSN_RE, self.CLASS_SSN, self.TOKEN_ID),
            (self._ACCOUNT_RE, self.CLASS_ACCOUNT, self.TOKEN_ID),
        )

    async def push_chunk(self, chunk: str) -> dict[str, object]:
        """Accept one chunk and emit the safe prefix ahead of the overlap tail."""
        await asyncio.sleep(0)
        async with self._lock:
            emitted = self._push_unlocked(chunk)
            return self._view(emitted)

    async def flush(self) -> dict[str, object]:
        """Emit the overlap tail after the caller has finished the stream."""
        await asyncio.sleep(0)
        async with self._lock:
            emitted = self._flush_unlocked()
            return self._view(emitted)

    async def redact_stream(self, chunks: list[str]) -> dict[str, object]:
        """Redact a finite sequence of chunks the caller already holds."""
        parts: list[str] = []
        for chunk in chunks:
            viewed = await self.push_chunk(chunk)
            parts.append(str(viewed["emitted"]))
        flushed = await self.flush()
        parts.append(str(flushed["emitted"]))
        return {
            "redacted": "".join(parts),
            "audit_count": flushed["audit_count"],
            "class_counts": flushed["class_counts"],
            "mean_span": flushed["mean_span"],
            "mean_chunk": flushed["mean_chunk"],
            "redaction_density": flushed["redaction_density"],
        }

    async def audit_tuples(self) -> list[tuple[int, int, int]]:
        """Return ``(offset, length, class_code)`` rows. Text is not included."""
        async with self._lock:
            return [self.AUDIT.unpack(record) for record in self._audit]

    async def carry_length(self) -> int:
        """Characters held back so a marker can finish in a later chunk."""
        async with self._lock:
            return len(self._buffer)

    def _push_unlocked(self, chunk: str) -> str:
        if not isinstance(chunk, str):
            raise EngineKernelException("chunk must be a str")
        if len(chunk) > self.MAX_CHUNK:
            raise EngineKernelException(
                f"chunk length {len(chunk)} exceeds limit {self.MAX_CHUNK}"
            )
        if len(self._buffer) + len(chunk) > self.MAX_CHUNK + self.HOLD:
            raise EngineKernelException("overlap carry exceeded chunk limit")
        self._chunk_lengths.append(len(chunk))
        self._buffer += chunk
        return self._drain_unlocked(final=False)

    def _flush_unlocked(self) -> str:
        return self._drain_unlocked(final=True)

    def _drain_unlocked(self, final: bool) -> str:
        if final:
            limit = len(self._buffer)
        else:
            limit = self._commit_limit(self._buffer)
        if limit <= 0:
            return ""
        piece = self._buffer[:limit]
        origin = self._buffer_origin
        redacted, records = self._redact(piece, origin)
        self._audit.extend(records)
        self._buffer = self._buffer[limit:]
        self._buffer_origin = origin + limit
        return redacted

    def _commit_limit(self, buffer: str) -> int:
        if len(buffer) <= self.HOLD:
            return 0
        limit = len(buffer) - self.HOLD
        scan_from = max(0, limit - self.MAX_SPAN)
        window = buffer[scan_from:]
        for regex, _class_code, _token in self._rules:
            for match in regex.finditer(window):
                start = scan_from + match.start()
                end = scan_from + match.end()
                if start < limit < end:
                    limit = start
        return limit

    def _redact(self, text: str, base_offset: int) -> tuple[str, list[bytes]]:
        found: list[tuple[int, int, int, str]] = []
        for regex, class_code, token in self._rules:
            for match in regex.finditer(text):
                found.append((match.start(), match.end(), class_code, token))
        found.sort(key=lambda item: (item[0], item[0] - item[1]))
        chosen: list[tuple[int, int, int, str]] = []
        cursor = 0
        for start, end, class_code, token in found:
            if start < cursor or end <= start:
                continue
            chosen.append((start, end, class_code, token))
            cursor = end
        parts: list[str] = []
        records: list[bytes] = []
        cursor = 0
        for start, end, class_code, token in chosen:
            parts.append(text[cursor:start])
            parts.append(token)
            length = end - start
            offset = base_offset + start
            if length > 0xFFFF:
                raise EngineKernelException("redaction span exceeds audit record width")
            if offset > 0xFFFFFFFF:
                raise EngineKernelException("stream offset exceeds audit record width")
            records.append(self.AUDIT.pack(offset, length, class_code))
            self._class_counts[class_code] = self._class_counts.get(class_code, 0) + 1
            self._spans.append(length)
            LOGGER.info(
                "redacted class=%d offset=%d length=%d",
                class_code,
                offset,
                length,
            )
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts), records

    def _view(self, emitted: str) -> dict[str, object]:
        if self._spans:
            mean_span = float(statistics.fmean(self._spans))
        else:
            mean_span = 0.0
        if len(self._spans) > 1:
            span_spread = float(statistics.pstdev(self._spans))
        else:
            span_spread = 0.0
        if self._chunk_lengths:
            mean_chunk = float(statistics.fmean(self._chunk_lengths))
            chunk_total = float(math.fsum(self._chunk_lengths))
        else:
            mean_chunk = 0.0
            chunk_total = 0.0
        if chunk_total > 0.0:
            density = math.fabs(float(math.fsum(self._spans)) / chunk_total)
        else:
            density = 0.0
        return {
            "emitted": emitted,
            "audit_count": len(self._audit),
            "held": len(self._buffer),
            "mean_span": mean_span,
            "span_spread": span_spread,
            "mean_chunk": mean_chunk,
            "redaction_density": density,
            "class_counts": dict(self._class_counts),
        }


async def run_scenario() -> dict[str, object]:
    engine = PrivilegedTokenRedactor()
    inbox: asyncio.Queue[str | None] = asyncio.Queue()
    chunks = [
        "section " * 20 + "ATTORNEY-CLIENT ",
        "PRIVILEGED memorandum for counsel at reviewer@example.com.",
        "Work product note. Account number 123456789012 remains sealed.",
        "Reference 219-09-9999 stays inside the hold file.",
    ]
    for chunk in chunks:
        await inbox.put(chunk)
    await inbox.put(None)
    parts: list[str] = []
    while True:
        item = await inbox.get()
        if item is None:
            break
        viewed = await engine.push_chunk(item)
        parts.append(str(viewed["emitted"]))
    tail = await engine.flush()
    parts.append(str(tail["emitted"]))
    redacted = "".join(parts)
    if "ATTORNEY-CLIENT" in redacted or "reviewer@example.com" in redacted:
        raise EngineKernelException("raw marker survived the scenario stream")
    if "219-09-9999" in redacted or "123456789012" in redacted:
        raise EngineKernelException("raw identifier survived the scenario stream")
    if engine.TOKEN_PRIVILEGED not in redacted or engine.TOKEN_ID not in redacted:
        raise EngineKernelException("stable tokens were not written")
    rows = await engine.audit_tuples()
    overlong_rejected = False
    try:
        await PrivilegedTokenRedactor().push_chunk("a" * (engine.MAX_CHUNK + 1))
    except EngineKernelException:
        overlong_rejected = True
    if not overlong_rejected:
        raise EngineKernelException("over-long chunk was accepted")
    summary = {
        "audit_count": len(rows),
        "class_counts": tail["class_counts"],
        "redaction_density": tail["redaction_density"],
        "overlong_rejected": overlong_rejected,
        "token_privileged": engine.TOKEN_PRIVILEGED,
        "token_id": engine.TOKEN_ID,
    }
    LOGGER.info("scenario complete audit_count=%s", len(rows))
    return summary


def main() -> int:
    summary = asyncio.run(run_scenario())
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
