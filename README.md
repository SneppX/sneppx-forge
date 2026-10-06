# SNEPPX Forge - Verified Model Registry

Registry + marketplace for models where every artifact is signed and
integrity-checked (Ed25519/Dilithium) before listing.

## Quickstart

```python
from sneppx_forge.registry import ModelRegistry

r = ModelRegistry(path="registry.json")
r.register("my-model", "/path/to/model.bin", kind="model", tags=["llm"])
r.verify("my-model")
print(r.stats())
```

REST API:

```bash
uvicorn sneppx_forge.app:create_app --factory
# then: GET /v1/models?tag=llm&kind=model, GET /v1/stats, POST /v1/models/{name}/verify
```

Docker: `docker build -t sneppx-forge . && docker run -p 8000:8000 sneppx-forge`

## Layout
- `src/sneppx_forge/registry.py` - persistent signed model registry (list/search/names/stats/verify/download)
- `src/sneppx_forge/api.py` - FastAPI CRUD + stats + verify
- `src/sneppx_forge/signing.py` - Ed25519 sign/verify with key-rotation allowlist
- `src/sneppx_forge/app.py` - uvicorn-ready ASGI app
- `tests/` - registry/app/signature tests

## Roadmap
- [x] signed listing lifecycle
- [x] search + stats
- [ ] pay-per-download / royalties
- [ ] marketplace UI

## License
MIT - part of the SneppX open-core ecosystem.
