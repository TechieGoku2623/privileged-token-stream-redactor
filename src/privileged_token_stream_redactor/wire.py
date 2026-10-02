"""Audit records and the FNV-1a chain that seals them."""

from __future__ import annotations

import struct

from .exceptions import EngineKernelException

AUDIT = struct.Struct("<IHH")
FNV64_OFFSET = 14695981039346656037
FNV64_PRIME = 1099511628211
_FNV_MASK = 0xFFFFFFFFFFFFFFFF


def pack_audit(offset: int, length: int, class_code: int) -> bytes:
    """Pack one ``(offset, length, class_code)`` audit record."""
    if not _field_ok(offset, 0xFFFFFFFF):
        raise EngineKernelException("stream offset exceeds audit width")
    if not _field_ok(length, 0xFFFF):
        raise EngineKernelException("redaction span exceeds audit width")
    if not _field_ok(class_code, 0xFFFF):
        raise EngineKernelException("class code exceeds audit width")
    return AUDIT.pack(offset, length, class_code)


def unpack_audit(payload: bytes) -> tuple[int, int, int]:
    """Unpack a record produced by :func:`pack_audit`."""
    if not isinstance(payload, (bytes, bytearray)) or len(payload) != AUDIT.size:
        raise EngineKernelException("audit record length mismatch")
    offset, length, class_code = AUDIT.unpack(payload)
    return int(offset), int(length), int(class_code)


def fold_fnv(state: int, payload: bytes) -> int:
    """Fold ``payload`` into a 64-bit FNV-1a chain."""
    if isinstance(state, bool) or not isinstance(state, int):
        raise EngineKernelException("FNV state must be an int")
    if not isinstance(payload, (bytes, bytearray)):
        raise EngineKernelException("audit payload must be bytes")
    folded = state & _FNV_MASK
    for byte in payload:
        folded ^= byte
        folded = (folded * FNV64_PRIME) & _FNV_MASK
    return folded


def _field_ok(value: int, limit: int) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 <= value <= limit
