"""Stream redactor with an overlap tail and a tamper-evident audit chain."""

from __future__ import annotations

import asyncio
import logging
import math
import re
import statistics
import struct
from collections import deque

from .exceptions import EngineKernelException
from .wire import AUDIT, FNV64_OFFSET, fold_fnv, pack_audit, unpack_audit

LOGGER = logging.getLogger("legal.privilege.redactor")

_BANNER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:"
    r"attorney[\s\-]*client[\s\-]+privileged"
    r"|attorney[\s\-]*client[\s\-]+privilege"
    r"|attorney[\s\-]*client[\s\-]+communication"
    r"|attorney[\s\-]*work[\s\-]*product"
    r"|privileged[\s\-]+and[\s\-]+confidential"
    r"|attorney[\s\-]*client"
    r"|work[\s\-]*product"
    r")"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_ACCOUNT_RE = re.compile(
    r"(?i)\b(?:account|acct)\s*(?:number|no\.?|#)?\s*[:#]?\s*\d{8,17}\b"
)
_LONG_DIGITS_RE = re.compile(r"\b\d{12,17}\b")


class PrivilegedTokenStreamRedactor:
    """Redact privilege banners and direct identifiers from caller-held text.

    A fixed overlap tail stays uncommitted so a marker split across chunks is
    still matched. Each redaction appends a struct audit record and folds those
    bytes into a running FNV-1a chain. The raw match is never logged.
    """

    CLASS_PRIVILEGED = 1
    CLASS_EMAIL = 2
    CLASS_SSN = 3
    CLASS_ACCOUNT = 4
    TOKEN_PRIVILEGED = "[PRIVILEGED]"
    TOKEN_ID = "[ID]"

    def __init__(self, max_chunk: int = 65536, overlap: int = 256) -> None:
        if max_chunk < 1 or overlap < 1:
            raise EngineKernelException("chunk and overlap limits must be positive")
        if struct.calcsize(AUDIT.format) != AUDIT.size:
            raise EngineKernelException("audit record width drifted")
        self.max_chunk = int(max_chunk)
        self.overlap = int(overlap)
        self._lock = asyncio.Lock()
        self._buffer = ""
        self._origin = 0
        self._boundaries: list[int] = []
        self._audits: list[bytes] = []
        self._fnv = FNV64_OFFSET
        self._redactions = 0
        self._chunks = 0
        self._split_repairs = 0
        self._spans: deque[int] = deque(maxlen=256)
        self._chunk_lengths: deque[int] = deque(maxlen=256)
        self._rules: tuple[tuple[re.Pattern[str], int, str, int], ...] = (
            (_BANNER_RE, self.CLASS_PRIVILEGED, self.TOKEN_PRIVILEGED, 0),
            (_EMAIL_RE, self.CLASS_EMAIL, self.TOKEN_ID, 1),
            (_SSN_RE, self.CLASS_SSN, self.TOKEN_ID, 2),
            (_ACCOUNT_RE, self.CLASS_ACCOUNT, self.TOKEN_ID, 3),
            (_LONG_DIGITS_RE, self.CLASS_ACCOUNT, self.TOKEN_ID, 4),
        )

    async def run(self, records: list[str]) -> dict[str, object]:
        """Redact a finite chunk sequence and return JSON-serializable counts."""
        await asyncio.sleep(0)
        async with self._lock:
            if not isinstance(records, (list, tuple)):
                raise EngineKernelException("records must be a sequence of chunks")
            parts: list[str] = []
            for chunk in records:
                parts.append(self._push_unlocked(chunk))
            parts.append(self._flush_unlocked())
            self._note_density()
            return {
                "redactions": self._redactions,
                "audit_fnv": self._fnv,
                "chunks": self._chunks,
                "split_repairs": self._split_repairs,
                "redacted": "".join(parts),
            }

    async def audit_rows(self) -> list[tuple[int, int, int]]:
        """Return ``(offset, length, class_code)`` rows. Text is omitted."""
        await asyncio.sleep(0)
        async with self._lock:
            return [unpack_audit(record) for record in self._audits]

    def _push_unlocked(self, chunk: str) -> str:
        if not isinstance(chunk, str):
            raise EngineKernelException("chunk must be a str")
        if len(chunk) > self.max_chunk:
            raise EngineKernelException("chunk length exceeds configured max")
        if len(self._buffer) + len(chunk) > self.max_chunk + self.overlap:
            raise EngineKernelException("overlap carry exceeded configured max")
        if self._buffer:
            self._boundaries.append(self._origin + len(self._buffer))
        self._buffer += chunk
        self._chunks += 1
        self._chunk_lengths.append(len(chunk))
        return self._drain(final=False)

    def _flush_unlocked(self) -> str:
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        if final:
            limit = len(self._buffer)
        else:
            limit = self._commit_limit()
        if limit <= 0:
            return ""
        piece = self._buffer[:limit]
        origin = self._origin
        redacted = self._redact(piece, origin)
        self._buffer = self._buffer[limit:]
        self._origin = origin + limit
        self._boundaries = [item for item in self._boundaries if item > self._origin]
        return redacted

    def _commit_limit(self) -> int:
        if len(self._buffer) <= self.overlap:
            return 0
        original = len(self._buffer) - self.overlap
        limit = original
        for start, end, _class_code, _token in self._collect(self._buffer):
            if start < original < end:
                limit = start
                break
        return limit

    def _collect(self, text: str) -> list[tuple[int, int, int, str]]:
        found: list[tuple[int, int, int, int, str]] = []
        for regex, class_code, token, priority in self._rules:
            for match in regex.finditer(text):
                found.append((match.start(), match.end(), priority, class_code, token))
        found.sort(key=lambda item: (item[0], item[2], item[0] - item[1]))
        chosen: list[tuple[int, int, int, str]] = []
        cursor = 0
        for start, end, _priority, class_code, token in found:
            if start < cursor or end <= start:
                continue
            chosen.append((start, end, class_code, token))
            cursor = end
        return chosen

    def _redact(self, text: str, origin: int) -> str:
        parts: list[str] = []
        cursor = 0
        for start, end, class_code, token in self._collect(text):
            parts.append(text[cursor:start])
            parts.append(token)
            record = pack_audit(origin + start, end - start, class_code)
            if len(record) != AUDIT.size:
                raise EngineKernelException("audit record width drifted")
            self._audits.append(record)
            self._fnv = fold_fnv(self._fnv, record)
            self._redactions += 1
            self._spans.append(end - start)
            absolute_start = origin + start
            absolute_end = origin + end
            for boundary in self._boundaries:
                if absolute_start < boundary < absolute_end:
                    self._split_repairs += 1
                    break
            LOGGER.info(
                "redacted class=%d offset=%d length=%d",
                class_code,
                absolute_start,
                end - start,
            )
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)

    def _note_density(self) -> None:
        if self._spans:
            mean_span = float(statistics.fmean(self._spans))
        else:
            mean_span = 0.0
        if len(self._spans) > 1:
            spread = float(statistics.pstdev(self._spans))
        else:
            spread = 0.0
        if self._chunk_lengths:
            total = float(math.fsum(self._chunk_lengths))
            covered = float(math.fsum(self._spans)) if self._spans else 0.0
            density = math.fabs(covered / total) if total else 0.0
        else:
            density = 0.0
        if self._redactions:
            LOGGER.info(
                "redaction density=%.6f mean_span=%.3f spread=%.3f chunks=%d",
                density,
                mean_span,
                spread,
                self._chunks,
            )
