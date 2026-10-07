# Node package: status in 0.1.0

**Read this before you unpack the node archive.** `blindpass-node-0.1.0-linux-x86_64.tar.zst` is an
unaccepted candidate. It has no installer and no operator procedure, and 0.1.0 documents no way for an
operator to enrol a node and complete a first workload. Everything below comes from the package manifest,
the [release layout](release-layout.md) and the [known limitations](../release/known-limitations.md).

## What the archive holds

- `bin/`: the broker (`blindpass-broker`), the node (`blindpass-node`), `blindpass-consumer`,
  `blindpass-provision`, `blindpass-credential-loader`, `blindpass-workload-client` and
  `blindpass-backup-probe`.
- `deploy/native/`: systemd unit, socket, sysusers and tmpfiles files, and `config/blindpass-node.env.example`.
  The files named `*probe*` are examples from the maintainers' host tests and must never be enabled as a
  production backup or workload.
- `lib/login/`: a pinned Node.js runtime, the private-login helper, Playwright and one headless Chromium
  shell. These bundled components have no dependency-scanner coverage in this release
  ([dependency evidence](../security/dependency-evidence-2026-10-06.md)).
- `manifest.json`: states `host_support: "unaccepted candidate; broker requires exact P01 profile and runtime checks"`.

## What is missing

- **No installer and no README.** Nothing creates the service accounts, directories, sockets or units, and
  nothing starts the broker before `blindpass-node enroll` needs its local socket.
- **No accepted host.** The broker's accepted scope is one exact tested profile: Ubuntu 24.04, systemd 255,
  no TPM. Debian 12 (systemd 252) and other hosts are not accepted, and a build that links there does not
  change that.
- **No end-to-end chapter.** The console's Enrollments page shows a one-use token and a
  `blindpass-node enroll --controller … --issuer-fingerprint … --token-stdin` command. The steps before
  and after that command (host setup, fingerprint approval, agent enrolment, policy, request, approval,
  delivery) are not described for operators.
- **The MCP package returns a fixed failure without a broker.** The npm package's `request_secret` answers
  `Operation failed` when no broker or store is configured, so a clean install is not evidence of secret
  delivery ([known limitations](../release/known-limitations.md)).

## What exists outside this release

The maintainers run enrolment, grants, browser handoff, backup and recovery workloads in disposable QEMU
guests through test harnesses that are part of the source repository and not part of any release asset. Their
records are linked from [known limitations](../release/known-limitations.md). They show that the pieces work
together on the tested profile; they are not instructions for an operator and are not an acceptance.

If you need a node before a documented procedure exists, ask the maintainers; do not assemble a broker from
the unit files.
