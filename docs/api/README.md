# SPS API reference

[openapi.yaml](openapi.yaml) is a manually maintained snapshot of existing SPS routes. It is not a complete generated schema, a release declaration, or the API for the proposed fleet controller. Route schemas and handlers in [SPS routes](../../packages/sps-server/src/routes) remain the implementation authority.

## Coverage

The snapshot covers liveness/readiness, user auth and locale preferences, workspace/policy management, agent enrollment/token minting, human secret provisioning, selected exchange paths, billing and analytics. Some advanced exchange/guest flows require reading source. Existing commercial routes remain documented for maintenance, while expansion is [frozen](../product/Roadmap.md#freeze-register).

The local server entry is an example endpoint. Configure your deployment's API URL explicitly; this documentation does not verify hosted service availability.

## Authentication modes

- Dashboard administration uses user bearer access tokens.
- With `SPS_HOSTED_MODE=1`, login/register/refresh set `sps_refresh_token` as an `HttpOnly`, `SameSite=Lax` cookie scoped to `/api/v2/auth`; `Secure` is applied in production or when HTTPS is detected. A configured cookie-domain override is optional.
- Hosted non-test responses omit the raw refresh token. `NODE_ENV=test` hosted responses also include it in JSON; non-hosted responses return it in JSON. `/auth/refresh` currently accepts a body token before a cookie even in hosted mode. This is not a cookie-only API contract.
- Both frontends retain `localStorage` compatibility paths for returned body tokens. See [authentication storage](../security/blindpass-threat-model.md#authentication-storage) for the current exposure/cleanup limits.
- Agent bootstrap uses `x-agent-api-key` on `POST /api/v2/agents/token`; operational routes use agent bearer JWTs. External issuer/JWKS validation is optional and does not attest local OS workload identity.
- Browser metadata/submit requests use scoped signatures; use the API origin configured into the frontend. Query-controlled `api_url` overrides are rejected by the input-page design.

Auth responses include `preferred_locale`; registration and `PATCH /api/v2/auth/locale` persist supported preferences. Cookie behavior, JSON fields and locale details should be updated together when the route implementation changes.

## Related contracts

- [Exchange policy](../guides/policy.md): implemented RBAC, full-document replacement and optimistic concurrency.
- [Self-hosting](../guides/self-hosting.md): API/frontend origins, state and proxy configuration.
- [Current architecture](../architecture/README.md): provisioning and exchange boundaries.
- [Proposed product specification](../product/Specification.md): new node/workload grants and browser sessions, not yet represented by this snapshot.
