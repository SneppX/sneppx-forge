import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sneppx_forge.ed25519 import keypair  # noqa: E402
from sneppx_forge.registry import ModelRegistry  # noqa: E402
from sneppx_forge.signing import sign_bytes, verify_payload  # noqa: E402


def test_register_get_list():
    r = ModelRegistry()
    r.register("m1", "m1.bin")
    assert r.get("m1")["uri"] == "m1.bin"
    assert len(r.list()) == 1
    r.unregister("m1")
    assert r.get("m1") is None
    assert r.list() == []


def test_sign_verify_roundtrip(tmp_path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"\x00\x01" * 200)
    data = f.read_bytes()
    pk, sk = keypair()
    sig = sign_bytes(data, sk, key_id="team-a")
    ok, det = verify_payload(data, sig)
    assert ok is True
    assert det["signer"] == "team-a"
    assert verify_payload(data, {"algorithm": "other"})[0] is False
    assert verify_payload(b"other", sig)[0] is False


def test_register_sign_verify(tmp_path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"payload")
    pk, sk = keypair()
    sig = sign_bytes(f.read_bytes(), sk)
    r = ModelRegistry()
    r.register("m1", str(f), signature=sig)
    assert r.get("m1")["verified"] is True
    ok, _ = r.verify("m1")
    assert ok is True
    r.register("m2", "remote://m2.bin", signature=sig)
    assert r.get("m2")["verified"] is False
    assert r.verify("m2")[0] is False


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "reg.json"
    r1 = ModelRegistry()
    r1.register("a", "a.bin")
    r1.save(str(p))
    r2 = ModelRegistry(path=str(p))
    assert r2.get("a")["uri"] == "a.bin"


def test_tampered_digest_rejects(tmp_path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"original")
    pk, sk = keypair()
    sig = sign_bytes(f.read_bytes(), sk)
    r = ModelRegistry()
    r.register("m1", str(f), signature=sig)
    assert r.get("m1")["verified"] is True
    f.write_bytes(b"tampered")
    ok, det = r.verify("m1")
    assert ok is False
    assert "hash" in det["error"]