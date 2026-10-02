# P05 completion review and gate record — 2026-10-02

**Status: P05 is not accepted.** This record closes the 2026-10-02 review: it lists
what was fixed, what each gate actually returned on the final working tree, what the
VM runs found, and what remains unestablished. Everything is uncommitted on top of
`1a37bbe`; nothing was pushed. The authoritative plan is the vault
[P05 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/05-workflows-and-clients.md)
(decisions P05-D11 to P05-D18) and its paired test plan.

Detail for each slice is in the per-slice records indexed in [docs/README.md](../../README.md):
[broker hardening](p05-broker-hardening-2026-10-02.md),
[scoped submit](p05-scoped-submit-2026-10-02.md),
[provisioning UI](p05-provisioning-ui-2026-10-02.md),
[harness hardening](p05-harness-hardening-2026-10-02.md),
[native service](p05-native-service-2026-10-02.md).

## Environment

Host: Linux 7.2.3-arch1-3, Node 26.10.0, rustc/cargo 1.98.1, disposable PostgreSQL
container on `127.0.0.1:5433`. Guest: pinned Ubuntu image (SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`), systemd
255.4-1ubuntu8.17, kernel 6.8.0-139-generic, Node 26.10.0, Chromium 145.0.7632.6,
Grafana OSS 13.2.3. Stock clients: Claude Code 2.1.286, codex-cli 0.159.3, run with
the host's existing logins against dummy data in a disposable VM; no real credential,
Source or website was involved.

## Host gates (final tree)

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | exit 0 |
| `npm run build` | exit 0 |
| `npm test` | exit 0: 23, 108 (console, includes 3 new fleet policy/workload cases), 42, 9, and 80 passed with 101 skipped (service-gated suites), plus node suites 57, 3, 108, 13, 2, 7, 147, all passing |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked --no-fail-fast -- --test-threads=1` (SQLite) | exit 0: 57 test binaries, 625 passed, 0 failed, 4 ignored |
| PostgreSQL controller suites (18 suites) | First run exit 101: 153 passed, 10 failed, all in `fleet_provisioning_submit`, `fleet_registry` and `fleet_roles`. Nine failed while connecting to the database in test setup: PostgreSQL error `53100` ×4 (`could not resize shared memory segment … No space left on device`; the container's `/dev/shm` is 64 MiB), `PoolTimedOut` ×4 and an unexpected EOF ×1. The tenth (`real_time_expiry_of_the_original_deadline_denies_metadata_and_submit`) got HTTP 503 instead of 200 in the same window; its cause was not separately confirmed. Rerunning the three suites alone passed: `fleet_provisioning_submit` 24, `fleet_registry` 4, `fleet_roles` 3 (exit 0). With the other 15 suites from the first run that is 163 passed and 0 failed, but **no single uninterrupted PostgreSQL run is green**. |
| `node --test tests/browser-handoff/*.test.mjs` with `P05_GRAFANA_HOME` set | exit 0: 180 pass, 0 fail, 0 skipped (without `P05_GRAFANA_HOME` three Grafana-backed files fail on import by design) |
| `python3 tests/browser-handoff/ai-client-result-test.py`, `ai-client-task-test.py` | 3 and 6 pass |
| Console Playwright, earlier on this tree: fleet, a11y and provisioning specs (preview, SQLite), plus the policy spec | 21 passed, and 2 passed; provisioning specs also passed on the embedded profile and on PostgreSQL. **Not rerun after the final edits**; no edit since touched the console or controller. |

## VM gates (disposable KVM guest, current binaries)

| Gate | Attempts | Result |
|---|---|---|
| Component gate (`private-helper-vm.sh`, fixture application, coordinator guest) | 3 | Run 1 passed every scenario but failed the new strict end-of-run leak check on units left `failed` by deliberate fault injection; the check was refined (control group must be empty, result reported) with its unit test written first. Run 2 exit 0 (3m59). Run 3 exit 0 (1m34) on the final binaries, after the helper pin and recovery fixes: `P05-COORDINATOR-VM … broker_sigkill_recovery=verified … login_count=2 recovery_relogin=0 copied_cookie_cancel=401`, `P05-HELPER-VM runtime=v26.10.0 … active_helper_units=0`, `P05-HELPER-VM-COMPLETE`. |
| Managed Grafana controller/node lifecycle (`BLINDPASS_P05_FLEET_BROWSER=1`, `grafana-managed`) | 3 | Runs 1 and 2 failed (below). Run 3 exit 0 in 6m36: `P05-FLEET-BROWSER-VM … broker_sigkill_recovery=verified … recovery_relogin=0 … copied_cookie_cancel=401 copied_cookie_restart=401` and `P05-MANAGED-FLEET-VM grafana=13.2.3 external_viewer=true setup_logins=1 operation_logins=2 recovery_logins=0 durable_mutations=403 recovery_api=401`, then the shared helper, supervisor, revoker, isolated-browser, journal and custody-clock stages and the end-of-run leak check. |
| Claude Code stock-client task (`BLINDPASS_P05_AI_CLIENT=claude`) | 3 | **1 pass in 3.** Runs 1 and 2 exited 0 with the whole tool sequence in the trace (request, status, two reads, cancel) but the client output did not parse to the strict `{"artifacts":N}` form (`parsedArtifacts: null`), so the strict check failed. Run 3 exit 0: `parsed_artifacts=12 stock_report_reads=2 stock_reconnects=1 copied_cookie_cancel=401 exact_runtime_removed=true source_session_canaries=absent closure_ms=7590`. |
| Codex stock-client task (`BLINDPASS_P05_AI_CLIENT=codex`) | 1 | Pass, exit 0: same assertions, `parsed_artifacts=12`, `closure_ms=25290`. |

The leak check reports `P05-UNIT-FAILED` for three login-helper instances and one native
supervisor instance in every run. They are `failed` units with `result=exit-code` and an
empty control group, left by scenarios that kill a helper or supervisor on purpose. A
unit with any process in its control group, or in any other state, fails the run.

## What the VM runs found (all fixed, with the evidence of each)

1. **Managed login always failed with `login_failed`.** The helper's new SPKI pin check
   asked CDP `Network.getCertificate` for both origins before typing. Chromium answers
   only for the origin of the document it is showing, so the application origin (which
   redirects to a separate issuer origin) never verified. The fixture recipe forces a
   single origin, so no fixture test could see it. The host test
   `private-login-grafana.test.mjs` reproduced it (red) and now passes. The helper now
   checks the login origin before anything is typed and the application origin after the
   login lands on it, before the session is published. **Limit:** the application origin
   is not checked before the OAuth redirect first reaches it.
2. **Recovery after a broker restart gave up for 60 s.** The recovery pass counted a wait
   for trusted time or the re-provisioned administrator credential as a failed revoke, and
   after three of those it backed off to 60 s, longer than the guest's 65 s wait. The unit
   test `recovery_waiting_for_an_input_retries_quickly_however_long_the_input_takes` was
   written first and failed with exactly the four `recovery_waiting` lines seen in the VM
   log; an unavailable input now retries every 5 s without counting a failure.
3. **Result-format diagnostics.** The two Claude failures were visible only as a null
   count. `answer_shape` now records a fixed-vocabulary class of an unparsed answer
   (`envelope`, `empty`, `fenced`, `not_json`, `json_not_object`, `json_keys`,
   `json_value`, `valid`) and never any of its text. The shape of the two failed answers
   was not recorded, because the diagnostic was added after them.
4. The guest scripts now forward the new broker log lines on failure
   (`startup_recovery_waiting`, `startup_recovery_complete`, `record_released`,
   `journal_unfenced`), the managed setup prints `login_failed` and `binding_mismatch`
   worker statuses, and the AI task verification names the failing sub-stage.

## Limits that matter

- The Claude task is **intermittent** on this prompt: 1 of 3 attempts passed. The strict
  parser was not relaxed. Whether to accept a fenced JSON answer is a decision for the
  owner; the earlier single passes (2026-10-01) do not show a pass rate.
- Codex closure took 25.29 s against a 30 s bound; one sample cannot show the margin.
- PostgreSQL gate: see the shared-memory note above. The container's `/dev/shm` limit is
  an environment property, not changed here.
- The Node 24.21.0 profile was **not run**: only Node 26.10.0 is installed on this host.

## Not established

- **P05.5 / P05-E02 (real restic and rest-server backup and restore):** blocked. ADR 0007
  (`block_pending_human_review`) needs a human decision. No restic, rest-server or Go
  toolchain was downloaded or run, and `tests/fleet/p05-backup.sh` exits 77 by design.
- **URL-elicitation variant of P05-E01:** unsupported for the selected clients (P05-D11).
  The supported human path is the authenticated operator console.
- Hosted CI (the dispatch-only KVM job and the Node 24/26 matrix), the desktop approval
  app and an Omarchy session, the console and input page against a **real broker**
  (the browser journeys use a JavaScript node fixture), two-host acceptance, the full
  lifetime/clock matrix and a 30-minute session soak.
- Owner acceptance review. Slice commits were not made.

## Cleanup

The subagent build directories under `target/agent-*` (gitignored) were deleted. The
VM harness removes its overlays and disposable keys; the scratch directory holds the logs
and is session-scoped.
