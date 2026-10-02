"""Roundtrip, happy path, and both redactor edge cases."""

from __future__ import annotations

import asyncio
import json
import unittest

from privileged_token_stream_redactor import (
    EngineKernelException,
    PrivilegedTokenStreamRedactor,
)
from privileged_token_stream_redactor.wire import (
    FNV64_OFFSET,
    fold_fnv,
    pack_audit,
    unpack_audit,
)


class RedactorEngineTest(unittest.TestCase):
    def test_wire_roundtrip(self) -> None:
        payload = pack_audit(120, 15, 1)
        self.assertEqual(len(payload), 8)
        self.assertEqual(unpack_audit(payload), (120, 15, 1))
        self.assertEqual(pack_audit(*unpack_audit(payload)), payload)
        state = fold_fnv(FNV64_OFFSET, payload)
        flipped = bytearray(payload)
        flipped[0] ^= 0x01
        self.assertNotEqual(fold_fnv(FNV64_OFFSET, bytes(flipped)), state)
        self.assertEqual(fold_fnv(state, b""), state)
        with self.assertRaises(EngineKernelException):
            unpack_audit(payload[:-1])

    def test_happy_path(self) -> None:
        asyncio.run(self._happy_path())

    async def _happy_path(self) -> None:
        chunks = [
            "The ATTORNEY-CLIENT PRIVILEGED memorandum is sealed.",
            "Contact reviewer@example.com about the file.",
            "SSN 219-09-9999 and account number 123456789012 stay on hold.",
        ]
        engine = PrivilegedTokenStreamRedactor()
        result = await engine.run(chunks)
        json.dumps(result)
        self.assertGreaterEqual(result["redactions"], 4)
        self.assertEqual(result["chunks"], 3)
        self.assertNotEqual(result["audit_fnv"], FNV64_OFFSET)
        text = str(result["redacted"])
        self.assertIn("[PRIVILEGED]", text)
        self.assertIn("[ID]", text)
        self.assertNotIn("reviewer@example.com", text)
        self.assertNotIn("219-09-9999", text)
        self.assertNotIn("123456789012", text)
        self.assertNotIn("ATTORNEY-CLIENT", text)
        rows = await engine.audit_rows()
        classes = {row[2] for row in rows}
        self.assertTrue({1, 2, 3, 4}.issubset(classes))
        again = await PrivilegedTokenStreamRedactor().run(chunks)
        self.assertEqual(again["audit_fnv"], result["audit_fnv"])

    def test_edge_overlong_chunk(self) -> None:
        asyncio.run(self._edge_overlong_chunk())

    async def _edge_overlong_chunk(self) -> None:
        engine = PrivilegedTokenStreamRedactor(max_chunk=64)
        with self.assertRaises(EngineKernelException) as caught:
            await engine.run(["y" * 65])
        self.assertIn("max", str(caught.exception))
        viewed = await engine.run(["plain text"])
        self.assertEqual(viewed["chunks"], 1)
        self.assertEqual(viewed["redactions"], 0)
        self.assertEqual(viewed["redacted"], "plain text")
        self.assertEqual(viewed["audit_fnv"], FNV64_OFFSET)

    def test_edge_split_marker(self) -> None:
        asyncio.run(self._edge_split_marker())

    async def _edge_split_marker(self) -> None:
        engine = PrivilegedTokenStreamRedactor()
        result = await engine.run(
            [
                "distribution copy ATTORNEY-CLIENT ",
                "PRIVILEGED for counsel only",
            ]
        )
        self.assertGreaterEqual(result["split_repairs"], 1)
        self.assertEqual(
            result["redacted"],
            "distribution copy [PRIVILEGED] for counsel only",
        )
        self.assertNotEqual(result["audit_fnv"], FNV64_OFFSET)
        rows = await engine.audit_rows()
        self.assertTrue(any(row[2] == engine.CLASS_PRIVILEGED for row in rows))


if __name__ == "__main__":
    unittest.main()
