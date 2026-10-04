# Registry persistence

`ModelRegistry(path=...)` saves/loads JSON (entries include digest,
signature payload, verified flag). Verification is recomputed on demand via
`verify(name)` using the stored artifact digest, so persisted `verified`
values are advisory - re-verify after loading from an untrusted file.
