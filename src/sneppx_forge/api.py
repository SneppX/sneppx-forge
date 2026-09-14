from sneppx_forge.registry import ModelRegistry


def create_app(registry=None):
    """FastAPI app (imported lazily so core lib stays dependency-free)."""
    registry = registry or ModelRegistry()
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="SneppX Forge", version="0.1.0")

    @app.get("/v1/models")
    def list_models():
        return {"models": registry.list()}

    @app.post("/v1/models/{name}")
    def register(name: str, uri: str, version: str = "1.0.0",
                 signature: dict | None = None):
        return registry.register(name, uri, signature, version=version)

    @app.get("/v1/models/{name}")
    def get_model(name: str):
        entry = registry.get(name)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown model")
        return entry

    @app.delete("/v1/models/{name}")
    def unregister(name: str):
        entry = registry.unregister(name)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown model")
        return {"unregistered": name}

    @app.post("/v1/models/{name}/verify")
    def verify_model(name: str, body: dict | None = None):
        public_key = (body or {}).get("public_key")
        ok, detail = registry.verify(name, public_key=public_key)
        return {"verified": ok, "detail": detail}

    return app