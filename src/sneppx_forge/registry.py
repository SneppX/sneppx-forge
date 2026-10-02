"""Persistent, signed model registry for the SneppX Forge.

A listing is only marked ``verified`` once its Ed25519 signature payload has
been checked against the artifact (or an explicit public key). The registry
can be saved to / loaded from JSON so a marketplace can persist across runs.
"""

import hashlib
import json
import pathlib

from sneppx_forge.signing import ForgeError, verify_payload


class ModelRegistry:
    """JSON-persisted registry of signed model listings."""

    def __init__(self, path=None):
        self._models = {}
        self._next = 0
        self._path = path
        if path is not None and pathlib.Path(path).exists():
            self.load(path)

    # -- core registry ops -------------------------------------------------

    def register(self, name, uri, signature=None, *, version="1.0.0",
                 kind="model", tags=None):
        """Register (or update) a model listing.

        ``signature`` is an Ed25519 payload dict (see :mod:`sneppx_forge.signing`).
        ``digest`` of the local artifact is stored so verification is cheap.
        """
        digest = None
        try:
            data = self._read_artifact(uri)
            digest = hashlib.sha256(data).hexdigest()
        except (OSError, ValueError):
            data = None  # remote/non-local uri: verification runs against bytes later

        verified = False
        if signature is not None:
            if data is not None:
                verified, _ = verify_payload(data, signature)
            else:
                verified = False

        entry = {
            "id": self._next,
            "name": name,
            "uri": uri,
            "version": version,
            "kind": kind,
            "tags": list(tags or []),
            "digest": digest,
            "signature": signature,
            "verified": verified,
        }
        self._models[name] = entry
        self._next += 1
        return entry

    def get(self, name):
        return self._models.get(name)

    def list(self):
        return list(self._models.values())

    def search(self, tag=None):
        """Return list of entries that contain *tag* in their tags list.

        If *tag* is None, return all entries.
        """
        if tag is None:
            return self.list()
        return [e for e in self._models.values() if tag in (e.get("tags") or [])]

    def stats(self):
        """Return registry statistics: total, verified, unverified counts."""
        total = len(self._models)
        verified = sum(1 for e in self._models.values() if e.get("verified"))
        return {
            "total": total,
            "verified": verified,
            "unverified": total - verified,
        }

    def verify(self, name, public_key=None, artifact_bytes=None):
        """Verify a registered listing's signature at call time.

        Returns ``(ok, detail)``; ``artifact_bytes`` overrides bytes read from
        ``uri`` when the artifact is a local file.
        """
        entry = self._models.get(name)
        if entry is None:
            return False, {"error": "unknown model", "name": name}
        if entry["signature"] is None:
            return False, {"error": "not signed"}
        if artifact_bytes is None:
            try:
                artifact_bytes = self._read_artifact(entry["uri"])
            except (OSError, ValueError) as exc:
                return False, {"error": "cannot read artifact", "detail": str(exc)}
        ok, detail = verify_payload(artifact_bytes, entry["signature"], public_key=public_key)
        if ok and entry["digest"] and hashlib.sha256(artifact_bytes).hexdigest() != entry["digest"]:
            return False, {"error": "digest changed after registration"}
        if ok:
            entry["verified"] = True
        return ok, detail

    def download(self, name, dest_dir="."):
        """Download a registered model's artifact to *dest_dir*.

        Returns ``(path, detail)`` where *path* is the local file path.
        """
        entry = self._models.get(name)
        if entry is None:
            return None, {"error": "unknown model", "name": name}
        uri = entry["uri"]
        src = pathlib.Path(uri)
        if not src.is_file():
            return None, {"error": "not a local file", "uri": uri}
        dest = pathlib.Path(dest_dir) / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        return dest, {"name": name, "path": str(dest), "size": dest.stat().st_size}

    # -- persistence -------------------------------------------------------

    def save(self, path=None):
        dest = pathlib.Path(path) if path else self._path
        if dest is None:
            raise ValueError("no registry path configured")
        dest.write_text(json.dumps(self._serialize(), indent=2), encoding="utf-8")
        return dest

    def load(self, path=None):
        src = pathlib.Path(path) if path else self._path
        if src is None:
            raise ValueError("no registry path configured")
        data = json.loads(src.read_text(encoding="utf-8"))
        self._models = {}
        for entry in data.get("models", []):
            self._models[entry["name"]] = entry
        self._next = data.get("next", max([e["id"] + 1 for e in self._models.values()], default=0))
        self._path = str(src)
        return self

    def _serialize(self):
        return {"format": "sneppx-forge-registry", "next": self._next,
                "models": list(self._models.values())}

    @staticmethod
    def _read_artifact(uri):
        path = pathlib.Path(uri)
        if path.is_file():
            return path.read_bytes()
        raise ValueError("not a local file: %s" % uri)