# Start here: installing the BlindPass controller

This page takes you from downloaded release assets to a signed-in operator console on one machine. It is
written for an evaluation: a single host, throwaway certificates and names that exist only on your machine.
Use real DNS names and a real certificate for anything else. The two quickstarts it links are the reference
for every option, backups and recovery.

## What this release is

- **Status:** a pilot candidate. No phase review of the software it is built from is accepted, no hosted
  continuous-integration run of the release workflow has happened, and there is no support commitment
  ([status and limits](#status-and-limits)).
- **What you can do with it:** install the controller natively on Debian 12 or Ubuntu 24.04 (x86_64), or with
  Docker Compose, sign in as the first administrator, take and verify an encrypted backup, and read the
  upgrade, restore, recovery and handoff runbooks.
- **What you cannot do from these documents:** enrol a node and complete a workload. The node package is an
  unaccepted candidate with no installer ([node package status](node-candidate.md)).

## What you need before you start

| You need | Why |
|---|---|
| A Debian 12 or Ubuntu 24.04 x86_64 host with systemd and `sudo` (native), or a host with Docker and the Compose plugin (Compose) | The controller runs there |
| `zstd`, `openssl`, `curl`, `tar`, `python3` (native also needs `psql`) | Unpacking and checks |
| **PostgreSQL 16** for the recovery authority | A separate database that records which controller may serve. Debian 12 ships PostgreSQL 15, so add the PostgreSQL project's apt repository (below). Keep it off the controller's backup path; the evaluation steps put it on the same host, which is **not independent** and is only acceptable for evaluation |
| Two public HTTPS names, one for the console and one for the secret input page, each with a certificate | Both are configured exactly; the controller refuses requests for any other name |
| A reverse proxy (nginx or Caddy) in front of the controller | The packaged profiles require it; examples ship in `deploy/proxy/` |
| The downloaded assets and the release key fingerprint | [Verify them first](../release/README.md#verify-a-download) |

A port other than 443 changes one thing: the `Host` and `X-Forwarded-Host` headers the proxy sends must carry
the port (`blindpass.test:18443`), and so must the public URLs. The steps below do this with one `sed` command.

## Step 1: verify what you downloaded

Follow [Verify a download](../release/README.md#verify-a-download). It needs only `ssh-keygen` and
`sha256sum`, the public key file the maintainers sent you and the key fingerprint they announced through a
different channel. Do not unpack anything that fails either check.

## Step 2: pick a path

| | Native | Docker Compose |
|---|---|---|
| Host | Debian 12 or Ubuntu 24.04, x86_64, systemd | Any Docker host (x86_64 image) |
| Controller | systemd service run by a locked `blindpass` account | Container run as `10001:10001` with named volumes |
| Reference | [Native quickstart](native-quickstart.md) | [Compose quickstart](compose-quickstart.md) |
| Evaluation steps | [Below](#native-evaluation-on-one-host) | [Below](#docker-compose-evaluation-on-one-host) |

Both paths work the same way after installation. The controller never starts by itself: **every start
needs a fresh activation** granted in the authority database (`authority-activate.sql`). A plain
`systemctl restart` or `docker restart` therefore ends with `startup_failed` and reason `fenced`; stop the
service, run `authority-activate.sql` again and start it. The units use `Restart=no` for that reason.

## Native evaluation on one host

Verification note: the PostgreSQL apt commands and the installer sequence below were run on a clean Debian 12
guest by the P07 dry run (2026-10-06); the SQL-over-stdin form, the `sed` edit, the certificate command and
`nginx -t` were checked separately on a workstation. Names `blindpass.test` and `input.test` and port 18443
are examples.

1. **Install the tools and PostgreSQL 16.**

   ```sh
   sudo apt-get update
   sudo apt-get install -y zstd nginx curl postgresql-common
   sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y   # adds the PostgreSQL project's apt repository
   sudo apt-get install -y postgresql-16
   ```

2. **Unpack the controller archive** (the files in this guide are inside it).

   ```sh
   tar --zstd -xf blindpass-controller-0.1.0-linux-x86_64.tar.zst
   cd blindpass-controller-0.1.0-linux-x86_64
   ./deploy/native/install.sh --verify-only
   ```

3. **Create the recovery authority** in its own database with a runtime role, and write the runtime URL to a
   private file. Loopback needs no TLS options.

   ```sh
   PSQL="sudo -u postgres psql -v ON_ERROR_STOP=1"
   RUNTIME_PASSWORD=$(openssl rand -hex 24)
   $PSQL -c "CREATE DATABASE bpauthority"
   $PSQL -d bpauthority -f - < deploy/controller/recovery-authority.sql
   $PSQL -c "CREATE ROLE bp_runtime LOGIN PASSWORD '$RUNTIME_PASSWORD'"
   $PSQL -d bpauthority -v runtime_role=bp_runtime -f - < deploy/controller/authority-runtime-role.sql
   sudo install -d -m 0700 /root/private
   sudo sh -c "umask 077; printf 'postgresql://bp_runtime:%s@127.0.0.1:5432/bpauthority' '$RUNTIME_PASSWORD' > /root/private/authority-url"
   ```

4. **Install, create the keys, register, initialise, activate and start.**

   ```sh
   sudo ./deploy/native/install.sh --public-url https://blindpass.test:18443 --ui-url https://input.test:18443 \
     --authority-url-file /root/private/authority-url --tenant-id evaluation --owner-id evaluation-native --initialize-keys
   ISSUER=$(sudo -u blindpass blindpass keys issuer-id)
   AUTH="$PSQL -d bpauthority -v tenant=evaluation -v owner=evaluation-native -v issuer=$ISSUER"
   $AUTH -f - < deploy/controller/authority-register.sql
   sudo ./deploy/native/install.sh --initialize
   $AUTH -f - < deploy/controller/authority-activate.sql
   sudo ./deploy/native/install.sh --start     # waits up to 20 s for readiness; exits 1 with the reason otherwise
   curl --fail http://127.0.0.1:3200/readyz     # {"ok":true,...} once the activation is consumed
   ```

5. **Put the HTTPS edge in front of it.** The nginx example listens on 443 and names `blindpass.example`; this
   rewrites the names, the port and the two `Host` headers.

   ```sh
   sudo install -d -m 0755 /etc/nginx/blindpass
   sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
     -keyout /etc/nginx/blindpass/private-key.pem -out /etc/nginx/blindpass/fullchain.pem -subj "/CN=blindpass.test" \
     -addext "subjectAltName=DNS:blindpass.test,DNS:input.test"
   sed -e 's/listen 443/listen 18443/' -e 's/blindpass\.example/blindpass.test/g' -e 's/input\.example/input.test/g' \
     -e '/^ *proxy_set_header \(X-Forwarded-\)\{0,1\}Host /s/;$/:18443;/' deploy/proxy/nginx.conf.example \
     | sudo tee /etc/nginx/conf.d/blindpass.conf > /dev/null
   sudo nginx -t && sudo systemctl reload nginx
   curl --fail --cacert /etc/nginx/blindpass/fullchain.pem --resolve blindpass.test:18443:127.0.0.1 https://blindpass.test:18443/readyz
   ```

6. **Create the first administrator.** Mint a one-use token (valid 15 minutes) and open the console.

   ```sh
   sudo blindpass admin bootstrap-token
   ```

   Open `https://blindpass.test:18443/`. It redirects to `/setup`: paste the token, choose a username and a
   password of at least 12 characters. With no DNS entry for the names, tunnel the port from the machine that
   runs your browser (`ssh -N -L 127.0.0.1:18443:127.0.0.1:18443 you@host`) and start the browser with
   `--host-resolver-rules="MAP blindpass.test 127.0.0.1, MAP input.test 127.0.0.1"`; trust the self-signed
   certificate for the evaluation only.

Next: [backups](native-quickstart.md#provisioning-sequence) (the quickstart's custody sequence), the
[upgrade runbook](upgrade.md) and [restore and recovery](native-quickstart.md#restore-and-recovery-activation-on-the-native-package).

## Docker Compose evaluation on one host

The commands below ran against the files in this archive and the release image in the P07 verification
(see the evidence record linked from [status and limits](#status-and-limits)). `$DL` is the directory that
holds the verified downloads. Run everything from the unpacked controller archive.

1. **Unpack and load the image.** A stock Docker cannot `docker load` the `.oci.tar` asset; load the
   `.docker.tar` companion, which carries the same image content and is covered by the same signature.
   After publication the image can instead be pulled by the digest in `controller-image.digest`
   (`docker pull ghcr.io/atas-tech/blindpass-controller@sha256:…`); that registry path does not exist before the
   release is published.

   ```sh
   tar --zstd -xf "$DL"/blindpass-controller-0.1.0-linux-x86_64.tar.zst
   cd blindpass-controller-0.1.0-linux-x86_64
   docker load --input "$DL"/blindpass-controller-image-0.1.0-linux-amd64.docker.tar
   export BLINDPASS_CONTROLLER_IMAGE=ghcr.io/atas-tech/blindpass-controller:0.1.0
   docker image inspect --format '{{.Id}}' "$BLINDPASS_CONTROLLER_IMAGE"
   ```

2. **Choose the names, the port and the project settings.** These variables are read by every Compose command
   below; `BLINDPASS_TRUST_PROXY` is the exact address the edge container will have.

   ```sh
   export EVAL_PORT=18443
   export BLINDPASS_PUBLIC_URL=https://blindpass.test:$EVAL_PORT BLINDPASS_UI_BASE_URL=https://input.test:$EVAL_PORT
   export BLINDPASS_EDGE_SUBNET=172.29.6.0/24 BLINDPASS_CONTROLLER_IP=172.29.6.2 BLINDPASS_TRUST_PROXY=172.29.6.3
   export BLINDPASS_CONTROLLER_TENANT_ID=evaluation BLINDPASS_CONTROLLER_OWNER_ID=evaluation-compose
   export BLINDPASS_AUTHORITY_CONFIG_DIR=$PWD/eval/authority
   mkdir -p eval/authority eval/tls eval/edge && chmod 0700 eval eval/authority eval/tls
   P=blindpass-eval   # a project name of its own, so a real deployment named "blindpass" is never touched
   C="docker compose -p $P -f deploy/controller/compose.sqlite.yml -f deploy/controller/compose.initialize.yml"
   ```

3. **Create the keys and read the issuer ID.** Running the controller image once also creates the project's
   `${P}_edge` network, which the authority container joins next.

   ```sh
   $C --profile initialize run --rm -T keys-init
   ISSUER=$($C run --rm -T --no-deps controller keys issuer-id --directory /keys)
   echo "$ISSUER"    # ed25519-...
   ```

4. **Start the recovery authority** (PostgreSQL 16 with TLS, reachable from the controller as
   `authority.test`, at its own fixed address so it cannot take the controller's or the edge's). A non-loopback authority must use `sslmode=verify-full`, so this creates a small private
   certificate authority first.

   ```sh
   openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=evaluation authority CA" \
     -addext basicConstraints=critical,CA:TRUE -keyout eval/tls/ca.key -out eval/tls/ca.pem
   openssl req -newkey rsa:2048 -nodes -subj /CN=authority.test -keyout eval/tls/server.key -out eval/tls/server.csr
   printf 'subjectAltName=DNS:authority.test\nbasicConstraints=CA:FALSE\n' > eval/tls/ext.cnf
   openssl x509 -req -in eval/tls/server.csr -CA eval/tls/ca.pem -CAkey eval/tls/ca.key -CAcreateserial -days 30 \
     -extfile eval/tls/ext.cnf -out eval/tls/server.crt
   chmod 0600 eval/tls/*
   docker run --detach --name "$P-authority" --network "${P}_edge" --ip 172.29.6.5 --network-alias authority.test \
     --user 0 --mount type=bind,src="$PWD/eval/tls",dst=/tls --entrypoint /bin/sh -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
     postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea \
     -ec 'install -d -m 0700 -o postgres -g postgres /pgtls && install -m 0600 -o postgres -g postgres /tls/server.key /pgtls/server.key && install -m 0644 -o postgres -g postgres /tls/server.crt /pgtls/server.crt && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/pgtls/server.crt -c ssl_key_file=/pgtls/server.key'
   PSQL="docker exec -i $P-authority psql -X -q -t -A -U postgres -h 127.0.0.1 -v ON_ERROR_STOP=1"
   until $PSQL -d postgres -c 'SELECT 1' > /dev/null 2>&1; do sleep 1; done
   ```

5. **Create the authority database, the runtime role and the private URL file**, owned by the image's user.

   ```sh
   RUNTIME_PASSWORD=$(openssl rand -hex 24)
   $PSQL -d postgres -c 'CREATE DATABASE authority'
   $PSQL -d authority -f - < deploy/controller/recovery-authority.sql
   $PSQL -d authority -c "CREATE ROLE evaluation_runtime LOGIN PASSWORD '$RUNTIME_PASSWORD'"
   $PSQL -d authority -v runtime_role=evaluation_runtime -f - < deploy/controller/authority-runtime-role.sql
   printf 'postgresql://evaluation_runtime:%s@authority.test:5432/authority?sslmode=verify-full&sslrootcert=/authority/authority-ca.pem' \
     "$RUNTIME_PASSWORD" > eval/authority/authority-url
   cp eval/tls/ca.pem eval/authority/authority-ca.pem
   chmod 0600 eval/authority/*
   docker run --rm --user 0 --entrypoint /bin/chown --mount type=bind,src="$PWD/eval/authority",dst=/authority \
     "$BLINDPASS_CONTROLLER_IMAGE" -R 10001:10001 /authority
   ```

6. **Register, create the database, activate and start.**

   ```sh
   AUTH="$PSQL -d authority -v tenant=$BLINDPASS_CONTROLLER_TENANT_ID -v owner=$BLINDPASS_CONTROLLER_OWNER_ID -v issuer=$ISSUER"
   $AUTH -f - < deploy/controller/authority-register.sql
   $C run --rm -T controller migrate
   $AUTH -f - < deploy/controller/authority-activate.sql
   $C up -d controller
   ```

7. **Put the HTTPS edge in front of it** (an nginx container with the fixed address the controller trusts).

   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
     -keyout eval/edge/private-key.pem -out eval/edge/fullchain.pem -subj "/CN=blindpass.test" \
     -addext "subjectAltName=DNS:blindpass.test,DNS:input.test"
   sed -e 's#127\.0\.0\.1:3200#controller:3200#' -e 's/blindpass\.example/blindpass.test/g' -e 's/input\.example/input.test/g' \
     -e "/^ *proxy_set_header \\(X-Forwarded-\\)\\{0,1\\}Host /s/;\$/:$EVAL_PORT;/" deploy/proxy/nginx.conf.example > eval/edge/blindpass.conf
   printf 'events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n' > eval/edge/nginx.conf
   docker run --detach --name "$P-edge" --network "${P}_edge" --ip 172.29.6.3 --publish 127.0.0.1:$EVAL_PORT:443 \
     --mount type=bind,src="$PWD/eval/edge/nginx.conf",dst=/etc/nginx/nginx.conf,readonly \
     --mount type=bind,src="$PWD/eval/edge/blindpass.conf",dst=/etc/nginx/conf.d/blindpass.conf,readonly \
     --mount type=bind,src="$PWD/eval/edge",dst=/etc/nginx/blindpass,readonly nginx:stable-alpine
   until curl --silent --fail --cacert eval/edge/fullchain.pem --resolve blindpass.test:$EVAL_PORT:127.0.0.1 \
     https://blindpass.test:$EVAL_PORT/readyz; do sleep 1; done
   ```

8. **Create the first administrator.** The command prints a one-time temporary password to your terminal;
   sign in at `https://blindpass.test:18443/login` as `admin` and complete the forced password change. The
   browser needs the same name mapping and certificate trust as in the native steps.

   ```sh
   $C exec -T controller blindpass admin bootstrap
   ```

Tear the evaluation down in the same shell (this destroys its keys and database). The authority files are
owned by the image's user, so a root container removes them:

```sh
docker rm -f "$P-edge" "$P-authority"
$C down --volumes
docker run --rm --user 0 --entrypoint /bin/rm --mount type=bind,src="$PWD",dst=/w "$BLINDPASS_CONTROLLER_IMAGE" -rf /w/eval
```

## After the console is up

- Native and Compose use different first-administrator flows: native mints a one-use setup token for a
  `/setup` page; Compose prints a temporary password for the `admin` account. Both end in the console.
- **Back up before you rely on anything**, then verify the backup on a different machine; the recipient key
  that decrypts it must stay offline ([native](native-quickstart.md), [Compose](compose-quickstart.md)).
- If a sole administrator is locked out after repeated wrong passwords, see
  [operator sign-in limits](../security/operator-auth-and-headers.md) for the lock and the reset.
- Upgrading is [a runbook](upgrade.md), downgrade is restore-only, and a restored controller serves again only
  through the [protected recovery activation](recovery-activation.md).

## Status and limits

- Release status, supported hosts and open items: [known limitations](../release/known-limitations.md) and the
  [release process](../release/README.md). The node package: [node package status](node-candidate.md).
- The quickstarts end with their own "Status and limits" sections: the transport and ownership behaviour,
  the evidence behind each runbook and the parts that are not accepted.
- Both paths record the evaluation that produced the steps above in the
  [operator documentation record](../testing/evidence/p07-operator-docs-2026-10-06.md).
