# Controller Compose candidate

The [SQLite profile](../../deploy/controller/compose.sqlite.yml) and
[PostgreSQL profile](../../deploy/controller/compose.postgres.yml) run the Rust
controller with both embedded browser surfaces. They require Docker Compose,
a separately administered HTTPS edge, and explicit initialization. Brokers run
on native hosts. Complete P06 recovery, upgrades, migration and workflow parity
remain unfinished; these profiles are deployment candidates.

## Image and private state

Build from the repository root:

```sh
docker build -f deploy/controller/Dockerfile -t blindpass-controller:local .
```

The pinned bookworm builder produces the controller and co-located CLI. The
bookworm-slim runtime contains OpenSSL 3, CA certificates and notices, runs as
`10001:10001`, and embeds the console/input page. It contains no Node, browser,
Redis or broker runtime. The current base pins target x86_64. Registry publishing
and aarch64 execution are separate gates; a source template tag is not proof
that an image exists in GHCR.

Named `/data` and `/keys` volumes receive private `0700`, UID/GID 10001 roots
from the image. `/keys` is read-only while serving; `/data` is writable. The
root filesystem is read-only, all capabilities are dropped, no-new-privileges
is set, core dumps are disabled, and a private `/run` tmpfs holds the `0600`
administration socket. Container recreation retains keys and database; `/run`
is volatile. No host ports, Docker socket, systemd mount or host PID namespace
are configured. Do not use a network/FUSE filesystem for SQLite.

## SQLite initialization

Copy the [public configuration example](../../deploy/controller/.env.example)
to a protected local configuration file. Set the two exact HTTPS origins and
an exact edge peer IP on the configured subnet. Commands below use explicit
process environment; Compose loads `.env` according to its working/project
configuration, not the repository workspace scripts.

```sh
export BLINDPASS_CONTROLLER_IMAGE=blindpass-controller:local
export BLINDPASS_PUBLIC_URL=https://blindpass.example
export BLINDPASS_UI_BASE_URL=https://input.example
export BLINDPASS_EDGE_SUBNET=172.29.6.0/24
export BLINDPASS_CONTROLLER_IP=172.29.6.2
export BLINDPASS_TRUST_PROXY=172.29.6.3
# Use the same project and files for every command.
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  -f deploy/controller/compose.initialize.yml --profile initialize run --rm keys-init
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml run --rm controller migrate
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml up -d controller
```

`keys init` refuses existing/partial keys; it never overwrites trust. Ordinary
startup validates configuration and existing initialized state. Missing,
exposed or linked keys and absent/unsupported database state refuse serving.
Startup currently applies no migrations; locked verified upgrade migrations
are later P06 work. First initialization alone is the supported procedure here.

Initialize the first administrator with the local socket:

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  exec -T controller blindpass admin bootstrap
```

This explicitly prints a one-time temporary administrator password to the
operator's terminal. Keep it outside shared terminals, logs and evidence; log
in through the configured HTTPS console and complete the password change.
Repeated bootstrap refuses after administrator creation.

## PostgreSQL initialization

Use the PostgreSQL profile instead of the SQLite file in every command above.
Set `BLINDPASS_POSTGRES_PASSWORD_FILE` to a private host file containing a strong
password, and `BLINDPASS_DATABASE_CONFIG_DIR` to a prepared private directory
owned by `10001:10001`, mode `0700`. Its `database.url` file must be mode `0600`,
owned by 10001, containing the matching URL
`postgresql://blindpass:<percent-encoded-password>@postgres:5432/blindpass`.
Prepare those files through a private editor or secret-management tool; no
password belongs in an environment assignment, command argument, template or
committed `.env`.

The official pinned PostgreSQL 16 image reads its password from a Compose
secret file. The controller reads the URL from the read-only `/config` mount;
Docker's configured environment contains file paths. PostgreSQL's entrypoint
reads the password and exports it inside the container process environment;
it remains available to the database process for its lifetime. Container/host
administrators and authorized database processes therefore consume plaintext.
The controller consumes the protected URL while opening database connections
and keeps its connection configuration in process memory while running. The protected
URL and password files remain on host storage until the operator removes them.
The internal database network publishes no database port. This profile uses
plaintext PostgreSQL transport inside that private bridge; it does not assert
end-to-end database wire encryption. Configure verified database TLS separately
for a remote database.

The controller waits for PostgreSQL's health dependency, and the database
volume survives recreation. The first migrate command creates schema/tenant;
normal serving refuses an uninitialized database. SQLite↔PostgreSQL conversion
is unsupported: use a fresh deployment and explicit reenrollment.

## HTTPS edge and checks

Attach the separately administered edge to the project `blindpass_edge`
network with exactly the configured trusted IP (the example uses 172.29.6.3).
Use the [nginx](../../deploy/proxy/nginx.conf.example) or
[Caddy](../../deploy/proxy/Caddyfile.example) example, changing both backend
addresses from `127.0.0.1:3200` to `controller:3200`, replacing the certificate
paths and configuring the exact two public authorities. Publish only the
edge's HTTPS port and protect its private key. Both examples overwrite Host,
X-Forwarded-Host/Proto/For, remove Forwarded, add HSTS and discard request/error
logs that could carry signed links. The controller rejects untrusted direct
peers, malformed forwarded headers and mismatched authorities.

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml ps
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  exec -T controller blindpass-controller healthcheck
```

The built-in probe contacts only loopback `/readyz`, reads no controller keys
or database configuration, uses a two-second total transport bound and writes
only a fixed failure diagnostic. When using built-in controller TLS instead of
an edge, configure `BLINDPASS_HEALTH_TLS_NAME` and, for a private CA,
`BLINDPASS_HEALTH_CA_FILE`; verification is mandatory. Its loopback connection
requires a wildcard or loopback listener. The supplied Compose profiles use
plain private backend transport and required HTTPS proxy mode.

Stop with `docker compose ... down`. It retains named state volumes. Do not use
`down --volumes` on real state unless deliberately destroying it. Do not copy a
live SQLite database/WAL or clone these volumes as a migration: authenticated
complete backups, external ownership fencing, stale restore reconciliation and
interrupted transfer runbooks are still required P06 work.
