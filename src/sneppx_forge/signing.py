"""Ed25519 signing helpers for model manifests (compatible with sneppx-shield)."""

import hashlib

from sneppx_forge import ed25519


class ForgeError(Exception):
    """Raised for signature/verification failures in the registry."""


def sign_bytes(data, sk, key_id=None):
    """Create an Ed25519 signature payload ``dict`` for ``data``.

    Compatible with sneppx-shield's detached signature layout so artifacts
    cross-verify between forge and shield.
    """
    sig = ed25519.sign(sk, data)
    return {
        "algorithm": "ed25519",
        "message_sha256": hashlib.sha256(data).hexdigest(),
        "public_key": sk[32:].hex(),
        "signature": sig.hex(),
        "key_id": key_id,
    }


def verify_payload(data, payload, public_key=None, trusted_keys=None):
    """Return ``(ok, detail)`` for an Ed25519 signature payload.

    ``public_key`` (hex or bytes) overrides the key embedded in the payload.
    ``trusted_keys`` (iterable of hex/bytes) is a key-rotation allowlist: the
    effective public key must be present in it when provided.
    """
    if not isinstance(payload, dict) or payload.get("algorithm") != "ed25519":
        return False, {"error": "unsupported algorithm", "payload": payload}
    pk = public_key
    if pk is None:
        try:
            pk = bytes.fromhex(payload.get("public_key", ""))
        except (ValueError, TypeError):
            return False, {"error": "no public key"}
    if isinstance(pk, str):
        pk = bytes.fromhex(pk)
    if trusted_keys is not None:
        allowed = set()
        for k in trusted_keys:
            allowed.add(bytes.fromhex(k) if isinstance(k, str) else bytes(k))
        if pk not in allowed:
            return False, {"error": "untrusted key (rotated/not in allowlist)"}
    try:
        sig = bytes.fromhex(payload.get("signature", ""))
    except (ValueError, TypeError):
        return False, {"error": "unparsable signature"}
    if hashlib.sha256(data).hexdigest() != payload.get("message_sha256"):
        return False, {"error": "manifest hash mismatch"}
    ok = bool(ed25519.verify(pk, data, sig))
    if not ok:
        return False, {"error": "signature mismatch"}
    return True, {"signer": payload.get("key_id")}
