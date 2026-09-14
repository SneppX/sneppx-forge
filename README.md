# SNEPPX Forge - Verified Model Registry

Registry + marketplace for models where every artifact is signed and
integrity-checked (Ed25519/Dilithium) before listing.

> Status: skeleton (WIP)

## Layout
- `src/sneppx_forge/registry.py` - in-memory signed model registry
- `src/sneppx_forge/api.py` - FastAPI CRUD skeleton
- `tests/` - smoke tests

## Roadmap
- [ ] signed listing lifecycle
- [ ] search + streaming downloads
- [ ] pay-per-download / royalties
- [ ] private hosting

## License
MIT - part of the SneppX open-core ecosystem.
