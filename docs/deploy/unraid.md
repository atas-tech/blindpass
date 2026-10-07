# Controller on Unraid

Unraid runs the same controller image as the [Compose profile](compose-quickstart.md), through two templates:
[`blindpass-controller-sqlite.xml`](../../deploy/unraid/blindpass-controller-sqlite.xml) and
[`blindpass-controller-postgres.xml`](../../deploy/unraid/blindpass-controller-postgres.xml). The owner decided on
2026-10-07 that Unraid stays a supported controller path. The legacy SPS stack's five templates (API, dashboard,
Redis, input page, database) have no replacement and need no migration: the controller embeds the console and the
input page and needs no Redis.

## Status

- The templates and the image they run are release candidates. The image is built and tested through the Compose
  profile ([container profiles](../testing/evidence/p06-container-profiles-2026-10-02.md)).
- **Nothing has been run through an Unraid host or its GUI.** Evidence for Unraid, GHCR and restic remains open
  ([authority provisioning](../testing/evidence/p06-authority-provisioning-2026-10-04.md)). Treat this page as the
  Compose sequence mapped onto the templates, not as a tested Unraid procedure.
- Backup, restore and recovery are the Compose profile's, in [the Compose guide](compose-quickstart.md). The
  [known limitations](../release/known-limitations.md) apply.

## What the templates assume

| Assumption | Why |
|---|---|
| A custom Docker network named `blindpass-edge` with an HTTPS reverse proxy on it | The controller publishes no host port. The proxy examples are in `deploy/proxy/` and the [ingress page](controller-ingress.md) says what it must send |
| `BLINDPASS_TRUST_PROXY` set to the proxy's exact IP or a restricted CIDR | A boolean or wildcard is refused |
| Two exact HTTPS origins, `BLINDPASS_PUBLIC_URL` and `BLINDPASS_UI_BASE_URL` | Requests for any other name are refused |
| Private host directories owned by `10001:10001`, mode `0700`, with key and URL files `0600`, on a direct pool path such as `/mnt/cache/appdata/blindpass-controller/` | Never `/mnt/user` or a network or FUSE filesystem for SQLite |
| A separately administered PostgreSQL 16 recovery authority, for both templates | It records which controller may serve ([Recovery authority](compose-quickstart.md#recovery-authority)) |
| For the PostgreSQL template, a second PostgreSQL 16 service on a private network and a `database.url` file in the mounted `/config` directory | Database credentials never go inline in the template |

## Sequence

1. Get the image verified and loaded as in [Image and private state](compose-quickstart.md#image-and-private-state).
2. Create the private directories and the authority directory (`authority-url`, mode `0600`, and its CA file) as in
   the Compose guide.
3. Run the one-time steps outside the template, because the template only runs `serve`: keys initialisation and the
   issuer ID, the administrator's `authority-register.sql`, then `migrate`. The tested way is the Compose files in
   `deploy/controller/` ([SQLite](compose-quickstart.md#sqlite-initialization),
   [PostgreSQL](compose-quickstart.md#postgresql-initialization)), run with Docker Compose from an Unraid terminal. If
   you use `docker run` lines instead, they must reproduce the template's user, read-only root, dropped
   capabilities, mounts and `/run` tmpfs, and you must verify them yourself.
4. Fill the template fields: the two origins, the trusted edge peer, the tenant and owner names you registered, and
   the authority URL file. Leave **Autostart off**.
5. Grant the start with `authority-activate.sql`, then start the container. Every later start, including after a
   crash or reboot, needs a fresh activation; a start without one never becomes ready.
6. Create the first administrator with `docker exec` into the container
   (`blindpass admin bootstrap`, as in the Compose guide).

Upgrades, backups and recovery follow the [upgrade](upgrade.md) and [recovery](recovery-activation.md) pages.
