"""Run a realistic legal-hold chunk batch."""

from __future__ import annotations

import asyncio
import logging
import sys

from .engine import PrivilegedTokenStreamRedactor
from .exceptions import EngineKernelException


async def _batch() -> dict[str, object]:
    engine = PrivilegedTokenStreamRedactor()
    chunks = [
        "Hold memorandum. ATTORNEY-CLIENT ",
        "PRIVILEGED and prepared for counsel. ",
        "Route questions to reviewer@example.com. ",
        "The file cites 219-09-9999 under the hold. ",
        "Account number 123456789012 remains sealed. ",
        "Work-product draft stays with the review set.",
    ]
    result = await engine.run(chunks)
    redacted = str(result["redacted"])
    if "reviewer@example.com" in redacted or "219-09-9999" in redacted:
        raise EngineKernelException("raw identifier survived the batch")
    if "123456789012" in redacted or "ATTORNEY-CLIENT" in redacted:
        raise EngineKernelException("raw marker survived the batch")
    if engine.TOKEN_PRIVILEGED not in redacted or engine.TOKEN_ID not in redacted:
        raise EngineKernelException("stable tokens were not written")
    if int(result["split_repairs"]) < 1:
        raise EngineKernelException("split banner was not repaired")
    if int(result["redactions"]) < 4:
        raise EngineKernelException("expected markers were not counted")
    logging.getLogger("legal.privilege.redactor").info(
        "scenario complete redactions=%s chunks=%s split_repairs=%s",
        result["redactions"],
        result["chunks"],
        result["split_repairs"],
    )
    return result


def main() -> int:
    """Redact a caller-held memo split across chunks. Return 0."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    result = asyncio.run(_batch())
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
