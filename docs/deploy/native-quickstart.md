# Native controller candidate

The P06 controller archive contains both embedded web surfaces, the local CLI
and the native lifecycle scripts. Use a reviewed x86_64 artifact on Debian 12
or Ubuntu 24.04 with real systemd, Python 3, OpenSSL 3 and CA certificates.
No Docker, Redis or Node runtime is needed by the installed controller.
Other architectures and full deployment/recovery acceptance remain open.
See [release layout](release-layout.md) and [HTTPS ingress](controller-ingress.md).

Verify `SHA256SUMS` obtained through your trusted release channel before
extracting the archive. Checksums and its member manifest detect corruption;
they do not authenticate an untrusted publisher. In the extracted directory:

```bash
sha256sum --check SHA256SUMS
tar --zstd -xf blindpass-controller-0.1.0-linux-x86_64.tar.zst
cd blindpass-controller-0.1.0-linux-x86_64
./deploy/native/install.sh --verify-only
sudo ./deploy/native/install.sh --public-url https://blindpass.example \
  --ui-url https://input.example --initialize --start
```

The last command explicitly creates three independent private keys and the
initial SQLite database. It starts the controller behind the required proxy;
configure the [shipped nginx or Caddy example](controller-ingress.md) before
using its API/UI. The controller listens on loopback port 3200. Set the two
origins to your actual endpoints. The installer never evaluates shell config
and never infers missing trust from a service restart.

For built-in TLS, supply a matching private PEM pair instead of the proxy:

```bash
sudo ./deploy/native/install.sh --public-url https://blindpass.example:3200 \
  --tls-cert /root/private/fullchain.pem --tls-key /root/private/key.pem \
  --initialize --start
```

Both inputs must be regular single-link files with no group/other access or
symlink path components. The installer copies them to a root-only directory;
systemd passes them to the service with `LoadCredential`. TLS paths use unit
`Environment=` specifiers, since `EnvironmentFile` does not expand `%d`.
The initial listen address is still loopback; a remote direct-TLS deployment
requires the operator to set `BLINDPASS_LISTEN` in the protected config and
restart, with matching endpoint routing and firewall rules.

The dedicated locked `blindpass` system account has no login shell, home or
extra groups. Existing unmanaged accounts, units, state and program paths are
refused. Installed executables live under `/opt/blindpass/controller/0.1.0`,
selected by `current`; `/usr/local/bin` contains the two managed links.
`/etc/blindpass/controller.env` is root:blindpass 0640. Keys and data directories
are blindpass-owned 0700; keys are 0600. The service uses a private runtime
directory and a read-only root filesystem with only its data/runtime writable,
no capabilities, no new privileges, private devices/temp and restricted system
calls/namespaces. Core dumps are disabled.

```bash
sudo systemctl status blindpass-controller.service
curl --fail http://127.0.0.1:3200/readyz  # proxy mode, local probe only
sudo blindpass admin bootstrap-token
```

In TLS mode the probe uses `https://127.0.0.1:3200/readyz` and a matching trusted
certificate, rather than plaintext. Deliver the one-use bootstrap token
directly to its intended administrator; do not capture it in shared logs.
The controller consumes raw key plaintext in runtime memory for its lifetime;
systemd credential copies last for the unit lifetime. SQLite contains protected
application state, not a substitute for encrypted recovery backups.
During an explicit TLS install, the installer and its short-lived OpenSSL
validation subprocess consume the supplied PEM plaintext in memory until
their processes exit. They publish only the protected files and fixed status
messages, never PEM content or parser diagnostics.

The backup service/timer are installed **disabled and inactive**. No recovery
key or enable marker is created. Their command is a future slice-5 integration
point; do not enable them before the authenticated backup command and protected
recovery-key configuration are implemented and verified. Their names are
`blindpass-controller-backup.*`; existing broker backup probe units are separate.

A same-manifest reinstall preserves keys, config and database. A different
version or changed artifact is refused until the verified upgrade path lands.
Default startup validates config and requires existing initialized state;
it does not migrate, repair or replace missing state. Systemd may recreate an
empty `StateDirectory`, but serving still refuses a missing database. The
root-only initialization record prevents a later installer from treating lost
state as a new tenant. This local record is clonable metadata, **not** the P06
external recovery/ownership anchor.

After a full host reboot the existing controller clock guard can require
explicit reconciliation. This invalidates transient authority and operator
sessions; read the [test setup](https://github.com/atas-tech/blindpass/blob/main/docs/testing/README.md)
before running it:

```bash
sudo systemctl stop blindpass-controller.service
sudo systemctl start blindpass-controller-reconcile-clock.service
sudo systemctl start blindpass-controller.service
```

Default uninstall removes only managed controller programs and units, retaining
keys, data, TLS material, config, installation records and the system account:

```bash
sudo ./deploy/native/uninstall.sh
# The same extracted artifact can reinstall retained state without --initialize.
sudo ./deploy/native/install.sh --start
```

Explicit irreversible purge requires both flags:

```bash
sudo ./deploy/native/uninstall.sh --purge --confirm-purge blindpass-controller
```

Purge validates custody and refuses linked/unsafe state, removes controller keys,
data/config/TLS, and retains the locked account and a root-only **purged** custody
record. It leaves broker/node/probe units and unrelated files alone. An operator
may explicitly initialize a new tenant after this confirmed purge; that action
does not restore old authority. Interrupted setup that already created any key
material needs manual review and recovery; rerunning initialization never
overwrites it. Authenticated backup/restore, upgrades, migration and complete
three-profile workflow parity remain required by P06.
