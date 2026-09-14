from sneppx_forge.registry import ModelRegistry

_registry = ModelRegistry()


def create_app():
    """FastAPI app skeleton."""
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="SneppX Forge", version="0.1.0")

    @app.get("/v1/models")
    def list_models():
        return {"models": _registry.list()}

    @app.post("/v1/models/{name}")
    def register(name: str, uri: str, signature: str | None = None):
        return _registry.register(name, uri, signature)

    return app
