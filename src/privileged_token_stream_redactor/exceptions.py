"""Kernel faults for the privileged token stream redactor."""

from __future__ import annotations


class EngineKernelException(Exception):
    """Raised when a chunk cannot enter the redaction stream."""
