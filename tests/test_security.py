import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


FAKE_ITERM2 = types.ModuleType("iterm2")
FAKE_ITERM2.run_forever = lambda main: None
sys.modules.setdefault("iterm2", FAKE_ITERM2)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("iterm2_harness", ROOT / "iterm2-harness.py")
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)


class SecurityTests(unittest.TestCase):
    def test_v2_safe_defaults(self):
        self.assertEqual(h.VERSION, "2.0.0")
        self.assertEqual(h.DEFAULT_CONFIG["host"], "127.0.0.1")
        self.assertFalse(h.DEFAULT_CONFIG["file_access"]["enabled"])

    def test_allowed_path_does_not_accept_prefix_sibling(self):
        with tempfile.TemporaryDirectory() as td:
            allowed = os.path.join(td, "project")
            sibling = os.path.join(td, "project-secret", "x.txt")
            os.makedirs(allowed)
            os.makedirs(os.path.dirname(sibling))
            old = h.FILE_ACCESS
            try:
                h.FILE_ACCESS = {"enabled": True, "allowed_paths": [allowed]}
                ok, status, _ = h._file_access_check(sibling)
                self.assertFalse(ok)
                self.assertEqual(status, 403)
                inside = os.path.join(allowed, "x.txt")
                ok, _, resolved = h._file_access_check(inside)
                self.assertTrue(ok)
                self.assertEqual(resolved, os.path.realpath(inside))
            finally:
                h.FILE_ACCESS = old

    def test_new_token_storage_is_hash_addressable(self):
        token = "secret-token"
        info = {"device_name": "test", "scopes": ["terminal.read"]}
        self.assertTrue(h._token_hash(token).startswith("sha256:"))
        self.assertNotIn(token, h._token_hash(token))
        self.assertTrue(h._token_has_scope(info, "terminal.read"))
        self.assertFalse(h._token_has_scope(info, "files.read"))

    def test_scope_validation(self):
        self.assertEqual(h._normalize_scopes(None), ["terminal.read", "terminal.write"])
        self.assertEqual(h._normalize_scopes(["files.read"]), ["files.read"])
        self.assertIsNone(h._normalize_scopes(["root"]))

    def test_duplicate_content_length_is_rejected(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(
                b"POST /api/v1/auth/request HTTP/1.1\r\n"
                b"Content-Length: 2\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )
            reader.feed_eof()
            with self.assertRaises(h.HTTPRequestError) as ctx:
                await h.read_http_request(reader)
            self.assertEqual(ctx.exception.status, 400)
        asyncio.run(run())

    def test_private_iterm_rpc_removed(self):
        source = (ROOT / "iterm2-harness.py").read_text("utf-8")
        self.assertNotIn("iterm2.rpc._", source)
        self.assertNotIn("connection.websocket", source)
        self.assertIn("iterm2.run_forever(main)", source)


if __name__ == "__main__":
    unittest.main()
