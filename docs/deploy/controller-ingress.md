# Controller startup, readiness and HTTPS

These P06 component behaviors are implemented. Native/Compose installation,
encrypted recovery and the full profile matrix remain gated by the
[phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md).
Use the [private layout](release-layout.md) and initialize keys explicitly.

## State initialization and diagnostics

Run `check-config`, then explicit `migrate` under the configured service account
before the first `serve`. Production `serve` requires an existing database at
the current schema version. It does not create a SQLite file, create tables,
upgrade an older schema, or fill in missing tenant/issuer/clock metadata. A
missing mount, empty database or unsupported/incomplete schema causes startup
refusal. Do not run initialization to repair established state after a loss;
recover the original protected state through the reviewed recovery procedure.
The comprehensive backup/restore procedure is still unfinished.

The test-mode fixture path retains explicit test initialization behavior and
must never be enabled for a deployment. `BLINDPASS_TEST_MODE=1` is refused when
`BLINDPASS_PROXY_REQUIRED=1` (every packaged profile) or `NODE_ENV=production`,
and `check-config` prints a warning when test mode is on. Clock startup checks still apply to
existing state; a host reboot can require explicit clock reconciliation before
authority is available. This clock fence is not P06's future external recovery
anchor or ownership fence.

`/healthz` reports process liveness. `/readyz` keeps `ok` and
`checks.database` (`up`/`down`), returns 503 on failure and adds a bounded
`reason` only when unready. Actual database disconnects produce
`store_unavailable`; a changed schema marker produces `schema_mismatch`; a
persisted clock fence produces `recovery_required`. Database startup failures
emit the same fixed vocabulary in a `startup_failed` event, including
`state_missing`, `permissions_invalid` or `disk_full` when that failure is
identified. Values, file paths, database URLs and driver errors are omitted.
Configuration errors name only fixed configuration fields. A startup refusal
has no HTTP listener; a failed readiness response is not expected in that case.

These checks do not yet report a migration lock, external recovery generation
or external owner. Those gates must be implemented with their durable state in
the corresponding P06 slices; they cannot be inferred from a healthy database.
Readiness validates the current schema marker and clock/store availability;
full schema structure is validated at startup.

## Reverse-proxy mode

Packaged proxy configuration sets `BLINDPASS_PROXY_REQUIRED=1`. Its default
is `0` for compatibility with existing explicit-loopback development settings;
set it explicitly when using a production edge. Both configured public/UI
origins must use HTTPS. `BLINDPASS_TRUST_PROXY` names the immediate TCP peers
as comma-separated IPs or canonical CIDRs, for example
`127.0.0.1,::1` or a dedicated proxy network. Do not trust a general client
network. Booleans, wildcard networks, invalid masks and CIDRs with host bits
are refused. IPv4 and IPv6 families are matched separately.

The [nginx example](../../deploy/proxy/nginx.conf.example) and
[Caddy example](../../deploy/proxy/Caddyfile.example) provide the two reviewed
authority/header mappings below. They are configuration candidates: neither
edge binary is installed on the current host, so parser validation and real
edge execution remain part of the native/Compose rehearsals. Configure a trusted
certificate chain for both names and inspect syntax with the selected edge's
configuration validator before rollout. Request/runtime logs are disabled
because signed-link URIs must not enter logs; adding diagnostic logs requires
verified URI/header redaction. Header syntax follows
the upstream [nginx proxy documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
and [Caddy reverse-proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#headers).

The edge must terminate TLS and **overwrite**, not append, all four upstream
headers on every request:

| Header | Value sent to controller |
|---|---|
| `Host` | Reviewed public or UI authority, including an explicit port if configured |
| `X-Forwarded-Host` | The same reviewed authority as Host |
| `X-Forwarded-Proto` | Exactly `https` |
| `X-Forwarded-For` | One validated client IP from the edge's transport connection |

Remove the alternative `Forwarded` header. Do not copy user-provided values or
an unreviewed Host into these headers. A trusted chain requires an explicit
review of each hop and a single normalized header set at the controller edge.
The controller rejects missing, duplicated, appended or mismatched values with
403 and the fixed `proxy_required` error, before API/UI/preflight processing.
Only GET/HEAD `/healthz` and `/readyz` from actual loopback peers bypass the
edge check. A trusted request receives `Strict-Transport-Security:
max-age=31536000`; no subdomain policy is assumed. HSTS belongs to the TLS
terminator: the examples add it on every response and strip an upstream copy,
a plain-HTTP profile never emits it and a client's own `X-Forwarded-Proto` does
not make the controller emit it. Do not add `includeSubDomains` or `preload`
until every subdomain serves HTTPS under your control, and stage a short
`max-age` first if the hostname's HTTPS is not yet proven (see
[browser headers and HSTS scope](../security/operator-auth-and-headers.md#browser-headers-and-hsts-scope-s04)).

Native proxy mode defaults to loopback. A container may bind
`0.0.0.0:3200` only with required proxy mode and explicit trusted peers, or
with configured built-in TLS. Network isolation and no direct public port
publication remain part of the unfinished Compose profile. For legacy optional
proxy mode, forwarded IPs affect rate limiting only from configured transport
peers; untrusted forwarded values never establish client identity.

## Built-in TLS alternative

Configure both `BLINDPASS_TLS_CERT_FILE` and `BLINDPASS_TLS_KEY_FILE` and HTTPS
public/UI origins. Set `BLINDPASS_PROXY_REQUIRED=0` when clients connect directly
to this listener. Both PEM files must be private regular single-link files
(0600 recommended), owned by the service account or root, reached through
absolute paths without symlinks. The certificate file holds the leaf and any
intermediate chain; the private key must match it. Configuration validates them
before state initialization or listener binding. Certificate reads are bounded
to 256 KiB/16 chain entries; key reads to 16 KiB. No insecure certificate
verification setting is needed for clients; use a certificate trusted by them.

The reviewed rustls/ring stack provides TLS 1.2/1.3 and HTTP/1.1. Each handshake
has a five-second timeout, with at most 64 concurrent handshakes. Stalled peers
do not serialize all accepts; saturation frees slots after timeout. SIGTERM
drops pending handshake tasks through graceful server shutdown. HSTS is emitted
on HTTPS responses. Private PEM read buffers are wiped on drop; rustls retains
server key state in runtime memory until its configuration is released at
shutdown. Files remain plaintext at rest. This lifetime is separate from
encrypted backup custody and browser/service plaintext delivery.

Replace certificates through a controlled service restart; this implementation
does not automatically reload files. Test the chosen certificate chain, proxy
and endpoint on the actual target deployment. Component HTTPS tests do not
establish native systemd or Compose support.
