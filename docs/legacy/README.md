# Legacy documents

Documents about the retired SPS hosted stack, kept as history. The stack (`packages/sps-server`, `packages/dashboard`,
Redis, the five legacy Unraid templates and their images) was removed on 2026-10-07 under P08, on the owner's decision
that no installation or backup of it existed. Nothing here is maintained or supported.

| Document | What it describes |
|---|---|
| [Quick start](quickstart.md) | Running the SPS, dashboard and input page from source |
| [Self-hosting](self-hosting.md) | Configuration, TLS and state of the SPS stack |
| [Legacy Unraid templates](Unraid.md) | The five SPS templates |
| [Manual demos](Manual%20Demos.md) | Dummy-data exchange exercises against the SPS |
| [OpenAPI snapshot](openapi.yaml) | A manual snapshot of the SPS routes |

The SPS source, its 17 database migrations and the legacy templates are in git history: check out the last commit
before the removal commit. Frozen records of the SPS contract remain in place: `packages/contract-tests/fixtures/`,
[the P00 compatibility matrix](../product/p00-compatibility-matrix.md) and the dated evidence under `docs/testing/evidence/`.
