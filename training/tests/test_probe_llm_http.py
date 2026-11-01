"""Why (coverage doctrine): the live-probe loop's transport and answer
parsing are product code. A real local HTTP stub exercises the full
request/parse path through the loopback SSRF policy without any external
network; the remote-plain-HTTP refusal arm is pinned alongside it.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import probe_llm_limits as pl  # noqa: E402


class _ChatStub(BaseHTTPRequestHandler):
    """Minimal Ollama /api/chat stub for transport-contract tests."""

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        payload = json.dumps(
            {
                "model": body.get("model"),
                "message": {"role": "assistant", "content": '{"category": "rejection"}'},
                "done": True,
                "thinking": "",
                "total_duration": 1,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        """Silence the stub's stderr access log."""


class CallOllamaTransportTests(unittest.TestCase):
    """SSRF policy and the real loopback transport round trip."""

    def test_remote_plain_http_is_refused(self) -> None:
        """Why: the SSRF policy — plain http only on loopback — is the
        transport's admission rule.
        """
        original = pl.OLLAMA_URL
        try:
            pl.OLLAMA_URL = "http://remote.example/api/chat"
            with self.assertRaises(ValueError):
                pl.call_ollama("m", "s", "u", None, 16, 0.0, timeout_s=1.0)
        finally:
            pl.OLLAMA_URL = original

    def test_loopback_stub_round_trip(self) -> None:
        """Why: the full request/parse path runs against a real local
        server through the loopback policy.
        """
        server = HTTPServer(("127.0.0.1", 0), _ChatStub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        original = pl.OLLAMA_URL
        try:
            pl.OLLAMA_URL = f"http://127.0.0.1:{server.server_port}/api/chat"
            response = pl.call_ollama("granite-test", "system", "user", None, 16, 0.0, timeout_s=5.0)
        finally:
            pl.OLLAMA_URL = original
        self.assertEqual(response["message"]["content"], '{"category": "rejection"}')

    def test_parse_answer_contract(self) -> None:
        """Why: the answer extractor's success and refusal arms both run."""
        self.assertEqual(pl.parse_answer('prefix {"category": "rejection"} suffix'), {"category": "rejection"})
        self.assertIsNone(pl.parse_answer("no json here"))
        self.assertIsNone(pl.parse_answer("{broken"))


if __name__ == "__main__":
    unittest.main()
