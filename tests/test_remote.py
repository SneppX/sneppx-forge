import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sneppx_forge import cli  # noqa: E402
from sneppx_forge.ed25519 import keypair  # noqa: E402
from sneppx_forge.registry import ModelRegistry  # noqa: E402
from sneppx_forge.signing import sign_bytes  # noqa: E402


class _FakeForge(BaseHTTPRequestHandler):
    token = None
    registry = None

    def log_message(self, *a):
        return

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if _FakeForge.token:
            if self.headers.get("Authorization") != f"Bearer {_FakeForge.token}":
                return self._send(401, {"detail": "unauthorized"})
        name = self.path.split("/v1/models/")[1].split("/")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        ok, detail = _FakeForge.registry.verify(name, public_key=body.get("public_key"))
        self._send(200, {"verified": ok, "detail": detail})


def _serve(registry=None, token=None):
    _FakeForge.registry = registry or ModelRegistry()
    _FakeForge.token = token
    server = HTTPServer(("127.0.0.1", 0), _FakeForge)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server.server_address[1], server, thread


def _make_valid_registry(tmp_path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"payload" * 20)
    pk, sk = keypair()
    sig = sign_bytes(f.read_bytes(), sk)
    r = ModelRegistry()
    r.register("m1", str(f), signature=sig)
    return r


def test_verify_remote_ok(tmp_path, capsys):
    port, server, _ = _serve(_make_valid_registry(tmp_path))
    try:
        rc = cli.main(["verify", "m1", "--remote", f"http://127.0.0.1:{port}"])
    finally:
        server.shutdown()
    out = capsys.readouterr().out
    assert rc == 0
    assert "OK: signature verified remotely" in out


def test_verify_remote_fail_mismatch(tmp_path, capsys):
    r = _make_valid_registry(tmp_path)
    port, server, _ = _serve(r)
    try:
        rc = cli.main(["verify", "m1", "--remote", f"http://127.0.0.1:{port}",
                       "--public-key", bytes([7] * 32).hex()])
    finally:
        server.shutdown()
    err = capsys.readouterr().err
    assert rc == 1
    assert "FAIL:" in err


def test_verify_remote_unknown_model(tmp_path, capsys):
    port, server, _ = _serve(_make_valid_registry(tmp_path))
    try:
        rc = cli.main(["verify", "nope", "--remote", f"http://127.0.0.1:{port}"])
    finally:
        server.shutdown()
    assert rc == 1
    assert "unknown model" in capsys.readouterr().err


def test_verify_remote_auth_required(tmp_path, capsys):
    port, server, _ = _serve(_make_valid_registry(tmp_path), token="s3cret")
    try:
        rc = cli.main(["verify", "m1", "--remote", f"http://127.0.0.1:{port}"])
    finally:
        server.shutdown()
    assert rc == 2
    assert "unauthorized" in capsys.readouterr().err


def test_verify_remote_with_token(tmp_path, capsys):
    port, server, _ = _serve(_make_valid_registry(tmp_path), token="s3cret")
    try:
        rc = cli.main(["verify", "m1", "--remote", f"http://127.0.0.1:{port}",
                       "--token", "s3cret"])
    finally:
        server.shutdown()
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_verify_remote_connection_fail(tmp_path, capsys):
    rc = cli.main(["verify", "m1", "--remote", "http://127.0.0.1:1"])
    assert rc == 2
    assert "cannot reach" in capsys.readouterr().err