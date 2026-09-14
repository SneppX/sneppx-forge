import os

from sneppx_forge.registry import ModelRegistry


def create_app(registry=None, token=None):
    """FastAPI app (imported lazily so core lib stays dependency-free).

    *token* (defaults to the SNEPPX_FORGE_TOKEN env var): when set, every
    /v1 route requires an `Authorization: Bearer <token>` header.
    """
    registry = registry or ModelRegistry()
    token = token if token is not None else os.environ.get("SNEPPX_FORGE_TOKEN")
    from fastapi import Depends, FastAPI, Header, HTTPException

    app = FastAPI(title="SneppX Forge", version="0.1.0")

    def require_auth(authorization: str | None = Header(default=None)):
        if not token:
            return
        if authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="missing/invalid token")

    @app.get("/v1/models", dependencies=[Depends(require_auth)])
    def list_models():
        return {"models": registry.list()}

    @app.post("/v1/models/{name}", dependencies=[Depends(require_auth)])
    def register(name: str, uri: str, version: str = "1.0.0",
                 signature: dict | None = None):
        return registry.register(name, uri, signature, version=version)

    @app.get("/v1/models/{name}", dependencies=[Depends(require_auth)])
    def get_model(name: str):
        entry = registry.get(name)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown model")
        return entry

    @app.delete("/v1/models/{name}", dependencies=[Depends(require_auth)])
    def unregister(name: str):
        entry = registry.unregister(name)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown model")
        return {"unregistered": name}

    @app.post("/v1/models/{name}/verify", dependencies=[Depends(require_auth)])
    def verify_model(name: str, body: dict | None = None):
        public_key = (body or {}).get("public_key")
        ok, detail = registry.verify(name, public_key=public_key)
        return {"verified": ok, "detail": detail}

    return app