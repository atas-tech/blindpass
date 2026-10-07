# P06 serving faults, stock browser and loaded recovery on the packaged native controller — 2026-10-06

**Status:** two-guest QEMU/KVM runs on the uncommitted tree above `8a595ad` (x86-64 host, Ubuntu 24.04 and Debian 12 controller guests, Ubuntu 24.04 node guest, bookworm-baseline release archive rebuilt 2026-10-06). It closes the slice 9 rows "UI logout", "serving disk-full" and "stock browser" for the native profile with a **remote** controller (the node guest reaches the controller guest over verified HTTPS through the host forward, not loopback). It is not the stock AI-client (Claude Code or Codex) workflow, not Compose or PostgreSQL-controller coverage for these two faults, and not P06 acceptance, which remains false.

## What ran

`tests/fleet/p06-native-node-vm.py --scenario serving-faults`: the whole `main` recovery sequence (backup, fence, restore through the packaged unit, relay, review, attestation, one activation, node back online, ordinary grant), then:

| Stage | Behavior checked |
|---|---|
| `browser` (BR1) | Chromium 152 (`tests/fleet/p06-console-browser.mjs`) signs in to the **embedded** console over verified HTTPS, pinning the served leaf's public key (no verification disabled), reads the nodes page (node listed online) and the approvals page, with no CSP violation and no request outside the controller origin; UI sign-out returns to `/login`, an in-page API call is then refused and the old session cookie replayed in a fresh context is rejected |
| `ui_logout` (U1) | logout without CSRF and from a foreign `Origin` are refused with the session intact; a real logout returns 204; the session and a replay of its cookie are rejected; a second logout is refused; another session of the same operator and the node stay up |
| `disk_full` (D1, D2) | the controller's data directory is moved onto its own 96 MiB ext4 loop volume (the recovery authority's PostgreSQL stays on the root filesystem, like a separate authority host); one activation brings the controller back; every free block of that volume is then taken. D1 records readiness, an authenticated read, a new login and a logout under the full volume. The volume is freed **without restarting the process**. D2 records what it takes to serve again, then checks SQLite `integrity_check`, an unrelated session, completing the logout, a new login, the node seen again, and one ordinary grant approved, delivered and consumed |

## Results

All six matrix cells below exited 0 with every PASS line, including `L1` (no password, token or PEM private key in controller, backup, restore or stale-instance journals, nor in the node guest's broker or node journals). Loaded means `tests/deployment/loaded-bounds.py --factor 2` (32 busy loops plus an fsync disk writer on 16 CPUs, load average 28 to 45).

| Controller guest | Load | Node online after the restored controller started (`S4`) | D1 under a full volume | D2 node seen again after the fault restart |
|---|---|---|---|---|
| Ubuntu 24.04 | none | 1.4 s | readiness 503 `disk_full`; authenticated read, new login and logout all 503 | 2.4 s |
| Debian 12 | none | 1.4 s | same | 4.4 s |
| Ubuntu 24.04 | loaded, run 1 | 23.0 s | same | 2.9 s |
| Ubuntu 24.04 | loaded, run 2 | 24.1 s | same | 36.5 s |
| Ubuntu 24.04 | loaded, run 3 | 28.1 s | same | 29.5 s |
| Debian 12 | loaded | 3.9 s | same | 5.0 s |

The 120 s reconnect bound held in every cell. Reconnect time follows how long the node was cut off, not controller speed (node back-off, see the [loaded bounds record](p06-loaded-bounds-2026-10-06.md)): Debian's shorter fence-to-serve left the node on a short back-off. The earlier loaded run of the `main` scenario measured 62.5 s and 63.5 s.

### Findings from the observations

- **A full data volume fails closed everywhere.** Readiness answers 503 (`disk_full` when the store error is classified, `recovery_required` when the epoch check fails first; both were seen across runs), and so do authenticated reads, new logins and logout. Nothing answered success that did not hold: a logout that answers 204 is checked to have ended the session.
- **Space alone does not bring the controller back (P06-D12, owner-confirmed).** In all six cells the process stayed up and fenced (`503 recovery_required`, no restart, authority record unchanged) after the volume was freed; one ordinary activation and start made it ready in 0.3 to 0.6 s. The runbook step is already documented in the quickstart; this is the first VM evidence for the disk-full trigger.
- **Logout is not guaranteed during a storage fault.** While the volume is full, logout returns 503 and does not clear the cookie, so the session stays valid until logout is retried after recovery (or it expires). This is fail-closed in the sense that the controller never claims a logout it did not record, but an operator cannot end a session during the fault. Flagged for the owner; no code change made.
- No data loss or corruption: `PRAGMA integrity_check` is `ok` on a private copy of the live database after every fault, an unrelated session survived the fence and restart, and the ordinary grant afterwards worked.

## Harness defects found and fixed during the work

- The first disk-full design filled the root filesystem, which also hosts the guest's PostgreSQL authority; under load that stopped the authority for over two minutes, which says nothing about a production layout with a separate authority. The data directory now lives on its own volume.
- Polling the node list by running the CLI status command each second spent the controller's own login limit (10 an account a minute): a `429 login_rate_limited` failed two loaded runs. The poll now uses one operator session, the status gate runs once with retries, and later logins wait out a 429. This is harness behavior only; the limit is working as designed.
- Chromium's resolver and trust flags do not apply to Playwright's separate request client, so checks run as in-page `fetch`. A wrong pin (the test CA's key instead of the leaf's) failed with `ERR_CERT_AUTHORITY_INVALID`, which is the negative check for the pinning.
- One loaded run failed during guest provisioning (`apt-get` on the guest timed out) before the controller stage; rerun from scratch it passed.

## Limits

- Native profile only for these faults, SQLite store, one node, x86-64, one host.
- The disk-full fault covers the controller data volume on the native profile. The Compose profiles, including a PostgreSQL store, are in [p06-compose-disk-full](p06-compose-disk-full-2026-10-06.md). A full backup volume while serving and a full journal were not run.
- A stock Chromium only. No Firefox or Safari, no real DNS or public CA (test CA, key pinned), and the console pages checked are sign-in, nodes, approvals and sign-out, not the full P04 console suite.
- The Claude Code and Codex stock-client tasks of P05 were **not** run against a packaged controller. Checked 2026-10-06: the opt-in profile (`BLINDPASS_P05_AI_CLIENT`, `tests/browser-handoff/README.md`) needs a verified Grafana 13.2.3 distribution (`P05_GRAFANA_HOME` is unset and none is on this host; fetching one is a dependency addition that needs the Socket review first), runs its own controller and node inside one P05 guest rather than the packaged controller, and uses the host's logged-in Claude and Codex accounts. Both CLIs are installed here. Running it against a packaged profile means porting that guest setup onto the two-guest harness and spending those accounts' usage; that needs an owner go-ahead.
- Loaded runs use synthetic CPU and disk load only.
