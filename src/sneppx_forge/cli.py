import argparse
import http.client
import json
import pathlib
import sys
import urllib.parse

from sneppx_forge.signing import sign_bytes
from sneppx_forge.registry import ModelRegistry

from sneppx_forge import ed25519


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sneppx-forge", description="SneppX Forge - signed model registry")
    parser.add_argument("--version", action="version", version="sneppx-forge 0.1.0")
    parser.add_argument("--registry", default="sneppx-forge.json", help="persisted registry path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list all registered models")

    get = sub.add_parser("get", help="inspect a model entry")
    get.add_argument("name")

    reg = sub.add_parser("register", help="register a model")
    reg.add_argument("name")
    reg.add_argument("uri")
    reg.add_argument("--version", default="1.0.0")
    reg.add_argument("--secret-key", help="Ed25519 secret key hex (optional)")
    reg.add_argument("--tags", default="", help="comma-separated tags")

    verify = sub.add_parser("verify", help="verify a model's signature")
    verify.add_argument("name")
    verify.add_argument("--public-key", help="override public key hex")
    verify.add_argument("--remote", help="verify against a remote registry server, e.g. http://localhost:8010")
    verify.add_argument("--token", help="Bearer token for the remote server (or set SNEPPX_FORGE_TOKEN)")

    serve = sub.add_parser("serve", help="run the registry REST server (needs fastapi+uvicorn)")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8010)
    serve.add_argument("--token", help="require Bearer auth (default: $SNEPPX_FORGE_TOKEN)")

    rm = sub.add_parser("delete", help="unregister a model")
    rm.add_argument("name")

    args = parser.parse_args(argv)
    reg_path = pathlib.Path(args.registry)
    registry = ModelRegistry(path=str(reg_path) if reg_path.exists() else None)
    registry._path = str(reg_path)  # persist target

    if args.command == "list":
        print(json.dumps(registry.list(), indent=2))
        return 0

    if args.command == "get":
        entry = registry.get(args.name)
        if entry is None:
            print("unknown model", file=sys.stderr)
            return 1
        print(json.dumps(entry, indent=2))
        return 0

    if args.command == "register":
        sig_payload = None
        sk = _resolve_secret_key(args.secret_key) if args.secret_key else None
        if sk is not None:
            artifact_bytes = ModelRegistry._read_artifact(args.uri)
            sig_payload = sign_bytes(artifact_bytes, sk)
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        entry = registry.register(args.name, args.uri, sig_payload,
                                  version=args.version, tags=tags)
        registry.save()
        print(json.dumps(entry, indent=2))
        return 0

    if args.command == "verify":
        if args.remote:
            return _verify_remote(args)
        pk = bytes.fromhex(args.public_key) if args.public_key else None
        ok, detail = registry.verify(args.name, public_key=pk)
        if ok:
            print(f"OK: signature verified")
            return 0
        print(f"FAIL: {detail.get('error')}", file=sys.stderr)
        return 1

    if args.command == "serve":
        from sneppx_forge.api import create_app

        token = args.token or None
        app = create_app(registry=registry, token=token)
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    if args.command == "delete":
        removed = registry.unregister(args.name)
        registry.save()
        if removed is None:
            print("unknown model", file=sys.stderr)
            return 1
        print(f"removed {args.name}")
        return 0
    return 2


def _resolve_secret_key(value):
    if value.startswith("@"):
        text = pathlib.Path(value[1:]).read_text(encoding="utf-8").strip()
        try:
            return json.loads(text)["seed"]
        except (json.JSONDecodeError, KeyError):
            return text
    return value


def _http_json(method, url, headers=None, body=None):
    """Minimal stdlib HTTP client returning parsed JSON + status."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme or "http"
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    port = parsed.port or (443 if scheme == "https" else 80)
    conn = cls(parsed.hostname, port, timeout=15)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    payload = None if body is None else json.dumps(body)
    headers = dict(headers or {})
    if payload is not None:
        headers.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "replace")
    conn.close()
    try:
        parsed_json = json.loads(data)
    except (json.JSONDecodeError, ValueError):
        parsed_json = {"detail": data}
    return resp.status, parsed_json


def _verify_remote(args):
    import os

    token = args.token or os.environ.get("SNEPPX_FORGE_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"{args.remote.rstrip('/')}/v1/models/{urllib.parse.quote(args.name)}/verify"
    body = {}
    if args.public_key:
        body["public_key"] = args.public_key
    try:
        status, data = _http_json("POST", url, headers=headers, body=body)
    except OSError as exc:
        print(f"FAIL: cannot reach registry ({exc})", file=sys.stderr)
        return 2
    if status == 401:
        print(f"FAIL: unauthorized - set --token or SNEPPX_FORGE_TOKEN", file=sys.stderr)
        return 2
    if status == 404:
        print(f"FAIL: unknown model on registry", file=sys.stderr)
        return 2
    if status != 200:
        print(f"FAIL: registry error {status}: {data}", file=sys.stderr)
        return 2
    if data.get("verified"):
        print(f"OK: signature verified remotely ({args.name})")
        return 0
    detail = data.get("detail") or {}
    print(f"FAIL: {detail.get('error')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())