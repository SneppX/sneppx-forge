import argparse
import json
import pathlib
import sys

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
        pk = bytes.fromhex(args.public_key) if args.public_key else None
        ok, detail = registry.verify(args.name, public_key=pk)
        if ok:
            print(f"OK: signature verified")
            return 0
        print(f"FAIL: {detail.get('error')}", file=sys.stderr)
        return 1

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


if __name__ == "__main__":
    sys.exit(main())