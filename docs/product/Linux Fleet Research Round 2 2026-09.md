# Linux Fleet Research, Round Two

**Date:** 2026-09-12  
**Status:** Research findings. Section 1 is empirically verified on the local host; later sections are desk research.  
**Builds on:** [Native Linux Fleet Research](Native%20Linux%20Fleet%20Research%202026-09.md) · [Product Review](Product%20Review%202026-09.md) · [Pilot test plan](../testing/Native%20Linux%20Fleet%20Pilot.md)

Round one identified the host broker as "a substantial new security boundary" and flagged the systemd credential-socket authentication question as needing verification against a real implementation. This round verifies it, and revisits the competitive and demand picture for the fleet direction specifically, which the original review did not cover.

## Table of Contents

- [1. Verified: systemd credential socket authentication](#1-verified-systemd-credential-socket-authentication)
- [2. Competitive landscape for the fleet direction](#2-competitive-landscape-for-the-fleet-direction)
- [3. Omarchy as a beachhead](#3-omarchy-as-a-beachhead)
- [4. SPIRE reassessment, and a simpler baseline](#4-spire-reassessment-and-a-simpler-baseline)
- [5. Demand reality check](#5-demand-reality-check)
- [6. Corrections to round one](#6-corrections-to-round-one)
- [7. Impact on the pilot test plan](#7-impact-on-the-pilot-test-plan)
- [8. What this changes in the recommendation](#8-what-this-changes-in-the-recommendation)
- [9. Sources](#9-sources)

---

## 1. Verified: systemd credential socket authentication

**This is the load-bearing mechanism for the entire service-delivery mode.** If the broker cannot tell which unit is asking, it hands credentials to whoever connects first.

### 1.1 Test environment

| Property | Value |
|---|---|
| systemd | 261 (261.2-1-arch), TPM2 support compiled in |
| Kernel | 7.2.3-arch1-3 |
| Scope tested | **User service manager only** (`systemd-run --user`) |
| Method | Transient units, ephemeral socket in a scratch directory |
| System state changed | None persistent; no unit files installed, no privileged operations |

**Scope limitation, stated up front:** every result below comes from the *user* service manager. System-scope behaviour, where the connecting process runs as root or as the unit's `User=` account before `exec`, was **not** tested and must be verified in the disposable VMs the pilot plan already requires.

### 1.2 What systemd actually sends

A transient unit with `LoadCredential=testcred:/path/to/socket` connected to a listening socket. The server observed:

| Signal | Observed value |
|---|---|
| `getpeername()` | `@57f9b451fef1c998/unit/run-p3857971-i3883698.service/testcred` |
| `SO_PEERCRED` | `pid=3857973 uid=1000 gid=1000` |
| Peer `comm` | `(sh)` — the forked, not-yet-`exec`d service process |
| Peer cgroup | `0::/user.slice/…/app.slice/run-p3857971-i3883698.service` |

The credential was delivered and appeared in the unit's `$CREDENTIALS_DIRECTORY`. **The round-one claim that systemd encodes the unit and credential identifier in the connecting abstract socket name is confirmed**, with the observed format:

```
\0<random-hex>/unit/<unit-name>/<credential-id>
```

This is not undocumented behaviour. `systemd.exec(5)` on this host, at the paragraph following the `LoadCredential=` description, specifies it exactly:

> "If referencing an `AF_UNIX` stream socket to connect to, the connection will originate from an abstract namespace socket, that includes information about the unit and the credential ID in its socket name. Use `getpeername(2)` to query this information. […] **This functionality is useful for using a single listening socket to serve credentials to multiple consumers.**"

Two points matter. First, the documented purpose is **multiplexing, not authentication** — systemd presents the name as a way to tell which credential is wanted, never as proof of who is asking. Second, the mechanism dates to systemd v247, the same release that introduced `LoadCredential=`, and the upstream commit is explicit that the random prefix exists only to prevent abstract-namespace squatting, because that namespace is open to unprivileged users. The prefix is anti-squatting, not anti-spoofing.

Note the peer is a process inside the *target unit's own cgroup*, not PID 1. Round one described the caller as "the service-manager credential loader"; more precisely, in user scope it is the forked service process itself, before it executes the service binary.

### 1.3 The abstract socket name is trivially forgeable

An ordinary unprivileged process bound an abstract socket name of its own choosing and connected to the same socket:

```python
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.bind("\0" + "deadbeefdeadbeef/unit/postgresql.service/db-password")
c.connect(broker_socket)
```

The server saw exactly that name via `getpeername()` and delivered the credential:

| Signal | Genuine systemd request | Forged ordinary process |
|---|---|---|
| `getpeername()` | `@57f9b451…/unit/run-p3857971….service/testcred` | `@deadbeefdeadbeef/unit/postgresql.service/db-password` |
| `SO_PEERCRED` uid | 1000 | 1000 |
| Peer `comm` | `(sh)` | `python3` |
| **Peer cgroup** | `…/app.slice/run-p3857971-i3883698.service` | `…/app-Hyprland-xdg\x2dterminal\x2dexec-8b46c3d6.scope` |

**A broker that trusts the abstract socket name would have handed a database password to an arbitrary user process.** Round one's instinct — "those strings are routing metadata, not independent proof of authorization" — is now demonstrated rather than suspected.

The random prefix provides no help. Across three genuine requests it was `57f9b451fef1c998`, `b330b50f08114a8a`, and `97a12a47da070751` — **random per connection**, so a broker cannot learn, pin, or validate it.

### 1.4 The cgroup is the authoritative signal

The only field that separated the genuine request from the forgery was the peer's cgroup, which the kernel maintains and the client cannot set. System-scope cgroups resolve cleanly:

```
0::/system.slice/systemd-journald.service
0::/system.slice/NetworkManager.service
```

`SO_PEERPIDFD` is available on this host (confirmed working, kernel 7.2.3; the option was added in kernel 6.5). It returns a pidfd rather than a raw PID, which closes the PID-reuse race that `SO_PEERCRED` leaves open — the exact race the pilot plan raises as scenario I02. `libsystemd` is present, so `sd_pid_get_unit`-family resolution is available rather than hand-parsing `/proc`.

### 1.5 User-scope units cannot be secured this way at all

The test above was run in user scope, and that turned out to be the most consequential result. Look again at the uid column: **genuine and forged requests were both uid 1000.** They are indistinguishable by peer credentials.

The reason is architectural. Credential setup runs inside the forked child before the service's user is enforced, so:

| Scope | Connecting peer runs as |
|---|---|
| System units | `systemd-executor` child, **uid 0**, PID not 1 |
| User units | **the session user's own uid** |

For system units, uid 0 is a meaningful gate: only root can connect, and root could read `/run/credentials/` anyway. For user units there is no gate at all. **Any process belonging to that user can impersonate any of that user's units.**

**Recommendation: do not use socket-mode credential delivery for user-manager units in any security-relevant path.** Restrict the broker to system units under distinct service accounts, which is what round one proposed for the isolation profile in any case. This now has a concrete reason rather than a stylistic preference.

### 1.6 Required broker authentication sequence

```
1. Accept on a filesystem socket owned by root, mode 0600.
2. Read SO_PEERCRED. Require uid == 0. Reject user-manager peers outright.
3. Obtain SO_PEERPIDFD.                    ← pidfd, not PID; closes the reuse race
4. Resolve the pidfd to a unit + invocation ID via sd_pidfd_get_unit(),
   or D-Bus GetUnitByPIDFD.                 ← never sd_peer_get_* or /proc parsing
5. Read getpeername() ONLY as a routing hint for which credential is wanted.
6. Require that the unit from step 4 matches the unit named in step 5.
7. Check an administrator-controlled unit → credential mapping.
8. Release only the mapped credential. Deny everything else.
```

Steps 2, 3, 4 and 6 are the security boundary. Steps 5 and 7 are configuration.

Step 4 matters more than it looks. systemd's own documentation for the `sd_peer_get_*` family warns that those fields "are retrieved via `/proc/`, and hence are **not suitable for authorization purposes, as they are subject to races**." The pidfd variants, added in systemd v253, pin the process for the duration of the call. The invocation ID additionally distinguishes one run of a unit from a restart, which is the right granularity for a workload identity.

**Any implementation that reads the credential name from the socket name and skips steps 2 through 4 is exploitable by any local user**, as demonstrated above.

### 1.7 Failure is fail-open by default

A broker that errors does not cleanly abort service startup. Upstream issue 27373 records that there is no way for a credential socket to signal "this credential does not exist", so **a failing broker produces an empty credential file and the unit starts anyway**.

The pilot plan's scenario C04 requires that a service "never starts successfully with empty or partial credentials." systemd will not enforce that. **Every credential-consuming service must validate that its credential is present, non-empty and parseable at startup**, and the pilot must test that validation rather than assuming the platform provides it.

Related: each `LoadCredential=` line opens its own connection, so N credentials means N connections (upstream issue 34223).

### 1.8 Rotation is better than round one assumed

Round one stated that changing a broker's value does not refresh an already-loaded credential and the service needs an explicit restart. That is now only partly true. `RefreshOnReload=` is present in systemd 261 on this host and explicitly accepts `credentials` as a resource class, covering `LoadCredential=`, `ImportCredential=` and `SetCredential=` along with their encrypted counterparts.

So the accurate statement is: **rotation requires an explicit `systemctl reload`, not a full restart**, on systemd v260 and later, and only for units that opt in. There is still no push-based or TTL-driven refresh, and the reload must be triggered deliberately. Round one's warning against silently restarting unrelated services still stands, and now has a lighter-weight alternative to offer.

### 1.9 Also verified on this host

| Check | Result |
|---|---|
| `SO_PEERPIDFD` availability | Supported, kernel 7.2.3. The option landed in kernel 6.5 |
| `libsystemd` present | Yes, so `sd_pidfd_get_unit` is available rather than hand-parsing `/proc` |
| TPM2 | Present, reported as `yes +firmware`. Note the gate command is now `systemd-analyze has-tpm2`; `systemd-creds has-tpm2` is deprecated in 261 |
| `RefreshOnReload=` | Documented in `systemd.service(5)` and `systemd.exec(5)` |

**Silent TPM downgrade.** `systemd-creds encrypt --with-key=auto` falls back to host-key-only when no TPM is found but `/var/lib/systemd/` is on persistent media, **with no warning**. Protection then collapses to "root can read a file." Round one asked for TPM fallback to be visible; the concrete implementation is to gate provisioning on an explicit `systemd-analyze has-tpm2` check rather than trusting `auto`.

### 1.10 Open questions this test did not answer

| Question | Why it matters | Where to answer it |
|---|---|---|
| Does a system-scope unit's peer really arrive as uid 0 here? | Source reading says yes; not tested locally | Disposable VM, system-scope unit |
| Does a `DynamicUser=` unit resolve to a stable unit identity? | The isolation profile assumes distinct service accounts | Disposable VM |
| Can a process in a *different* user's session reach the socket? | Socket file permissions are the first gate, before any of the above | Disposable VM, multi-account |
| Does `LoadCredentialEncrypted=` change the socket protocol? | The pilot proposes TPM-bound custody | Disposable VM, with and without TPM |
| Broker stall and timeout semantics | Scenario C04 needs a bounded failure, and systemd's default is fail-open | Disposable VM |

---

## 2. Competitive landscape for the fleet direction

Round one's competitive work covered secret *provisioning*. The fleet direction competes in a different, busier market. Four capabilities separate the field:

- **(A)** a local daemon on the Linux host
- **(B)** OS-level workload attestation from protected execution context
- **(C)** per-request human approval
- **(D)** credential-less operation proxying, where the workload never holds the secret

### 2.1 Nobody ships all four

| Product | A | B | C | D | Notes |
|---|:-:|:-:|:-:|:-:|---|
| **Riptides** | yes | yes | no | yes | Linux kernel module, SPIFFE identity issued in-kernel at process start, secrets swapped in-kernel before TLS encryption. Technically the deepest overlap |
| **Aembit** | yes | partial | no | yes | Edge proxy plus split agent/controller on VMs. Attests via platform tokens, not OS process context. Free to 10 workloads, then $299/mo |
| **Teleport MWI** | yes | **yes** | no | no | `tbot` serves the SPIFFE Workload API over a Unix socket, with a real systemd attestor over D-Bus and UID/GID restriction. Hands out credentials rather than brokering. Enterprise pricing, roughly $50k floor |
| **Keycard** | no | no | yes | yes | Token-exchange broker with delegation chains and optional human approval for sensitive operations. Cloud-side only |
| **Bitwarden Agent Access SDK** | partial | no | **yes** | partial | Alpha. Human-in-the-loop approval per credential use with a CLI approval UI, then injects into child-process environment |
| **1Password Credential Broker** | no | no | no | yes | Public preview since July 2026, GA expected late 2026. Workload identity federation, CI and cloud shaped |
| **Britive / P0 / ConductorOne / Opal** | no | no | yes | no | Entitlement-grant approval workflows, minutes-to-hours, identity-provider shaped |
| **Pomerium / Cloudflare Access** | no | no | no | partial | Identity-aware proxies for north-south traffic |

**The gap is real but narrow.** It is capability C bound to capability B: per-request human approval tied to an attested *local process* identity, rather than an entitlement grant issued against a user account.

### 2.2 The open-source layer is commoditizing the proxy half

This is the part that should change planning. During 2026 a cluster of free tools shipped the credential-proxying idea:

| Project | Traction | What it does |
|---|---|---|
| **nono** | ~3.1k stars, 80+ contributors, led by a Sigstore founder | Agent sandbox plus trusted proxy. Pulls credentials from OS keyring, 1Password or Bitwarden and injects them only into approved API requests |
| **Infisical agent-vault** | ~2.1k stars | Go proxy that injects the authorization header mid-flight. Explicitly targets Claude Code and OpenClaw |
| **CyberArk Agent Guard** | Vendor-backed OSS | Secret injection plus MCP proxy auditing |
| **kloak** | ~246 stars | eBPF uprobes on TLS write, secrets confined to eBPF maps |
| **Anthropic sandbox-runtime** | First-party, free | Bubblewrap and seatbelt sandboxing with proxy network filtering |

**Selling "the agent never holds the credential" alone is no longer viable.** That claim is available free, from several projects, one of which has a security-credible maintainer and real adoption.

### 2.3 Two defensible positions remain

**First: systemd `LoadCredential=` socket delivery is unclaimed.** Every competitor above is proxy-shaped or file-shaped. None integrates with the native Linux service credential mechanism. Combined with the verified authentication sequence in [section 1](#16-required-broker-authentication-sequence), this is a genuine technical differentiator, and it serves the non-AI half of the fleet that no agent-security vendor addresses at all.

**Second: per-request approval bound to attested local process identity.** Keycard and Bitwarden have approval without attestation. Teleport and Riptides have attestation without approval. Joining them, surfaced in a desktop UI, is the actual product.

Lead with those two. Do not lead with credential-less access.

### 2.4 The Tailscale objection

Expect every technical evaluator to ask why Tailscale is not sufficient. The answer is specific: Tailscale access control lists are enforced at the **node** level, and tags are device-level. Multiple services on one host share that host's identity, so Tailscale cannot express "this process may call that API, that one may not." It solves transport, reachability and coarse identity, and it composes well underneath this design. It does not answer which process on the box is asking.

### 2.5 Pricing precedent exists, but not for this category

| Product | Price | Relevance |
|---|---|---|
| **Sandfly Security Home** | **$99/yr for 10 hosts** | Closest precedent: Linux security, small fleet, same buyer |
| Portainer Home & Student | $155/yr, 15 nodes | Free-under-N then flat is the accepted homelab shape |
| Fleet Premium | $7/host/month | Per-host pricing at this scale |
| Tailscale Personal Plus | $5/month | Device approval itself sits in the $18/user/month Premium tier |

Small-fleet Linux security sells at roughly $99 a year. **No incumbent has validated that small-fleet operators will pay for workload authorization specifically**, which is simultaneously the opportunity and the risk.

---

## 3. Omarchy as a beachhead

### 3.1 The audience is larger than round one assumed

Round one recorded Omarchy demand as untested. The adoption numbers are stronger than that implies:

| Metric | Value |
|---|---|
| GitHub stars | ~35,000 (late August 2026) |
| Quattro ISO downloads | 200,000 in 18 days (reported 2026-09-02) |
| Discord members | ~35,000 |
| Funding | ~$18.5M, including a $3M DigitalOcean pledge |
| Institutional use | 37signals runs it company-wide |

More importantly for this product, **Omarchy 4 ships ten AI coding command-line tools pre-wired**, plus Herdr, a multiplexer that tracks whether each agent is idle, working, blocked or done. The median Omarchy user is close to the target user. Critics reasonably note that ISO downloads are not retained users, and no public retention data exists.

### 3.2 Verified locally: the shell plugin cannot hold secrets

This was checked first-hand on the local Omarchy 4.0.3 install rather than taken from documentation online. The shipped shell README states:

> "Plugins run as unsandboxed code inside `omarchy-shell`. […] The scoped QML interfaces remove direct authentication-service and generic replacement-bar service lookups, but visual plugins still share and can traverse the ordinary host scene. Only add repos whose code you are willing to run."

And the plugin API source carries the same warning:

> "it is not a QML sandbox: visual plugins share the host object tree."

Two consequences:

1. **Any co-installed third-party plugin runs in the same process** and can walk the object graph to reach host objects. Secrets, custody keys, and approval authority must live in a separate privileged process, exactly as round one proposed. That proposal is now backed by the platform's own documentation.
2. **Omarchy itself already removes authentication-service lookups from the plugin surface.** The platform has deliberately decided that authentication does not belong in plugins. A BlindPass widget that held secrets would contradict the host platform's stated security model, which is a credibility problem, not merely a technical one.

The widget must be a thin, unprivileged notifier that talks to the broker over a Unix socket with peer-credential checks. It can display status and open an approval surface; it cannot be the approval surface.

### 3.3 Omarchy already occupies the adjacent bar space

The local install ships a first-party `agents` plugin at `/usr/share/omarchy/shell/plugins/agents/` with per-agent panels and assets for Claude, Codex and Fireworks. It reads usage records written by `omarchy-agent-usage-update` and displays subscription limits and token spend.

This is a display-only module, so it does not compete functionally. It does establish that the first party is already building agent-related bar surfaces, and it sets the visual and interaction conventions a third-party approval widget would need to match.

### 3.4 An asset round one did not account for

The operator running this review is already an Omarchy plugin author. The local install includes four plugins authored by them, among them **OmaSafe**, a plugin security scanner that inspects installed plugins and reviews candidates for source drift.

That is real ecosystem credibility in exactly the relevant niche: plugin security. It also means the publishing path, manifest conventions and marketplace mechanics are already understood.

The honest counterweight is that the OmaSafe repository currently shows no stars. Ecosystem familiarity is proven; audience reach is not.

### 3.5 No monetization precedent

No paid Omarchy plugin was found, the marketplace is community-run rather than operated by the first party, and there are no payment rails. The audience is Arch and free-software oriented. A first-party $4,000 plugin competition in August 2026 signals attention but not commerce.

**Implication:** ship the Omarchy widget free and open source as the demonstration surface. Monetize the broker and control plane on a small-fleet curve, free under about three hosts, then roughly $99 a year in Sandfly's shape.

---

## 4. SPIRE reassessment, and a simpler baseline

### 4.1 SPIRE's systemd attestor is weaker than a direct implementation

Round one recommended evaluating SPIRE "before implementing equivalent attestation and certificate machinery." That ordering should be inverted, for a specific reason rather than a general one about weight.

| Finding | Detail |
|---|---|
| Selector names | The selectors are **`systemd:id`** and **`systemd:fragment_path`**. There is no `systemd:unit` selector; round one's wording should be corrected |
| The attestor is PID-based | It calls D-Bus `GetUnitByPID` with the raw PID taken from the Workload API, which is exactly the race systemd's own documentation warns about |
| The fix was declined | Issue 6035 proposed moving to `SO_PEERPIDFD` with `GetUnitByPIDFD`. It was **closed as not-planned on 2026-06-05** |
| Partial mitigation | The `peertracker` component holds a `/proc/<pid>` directory handle and compares process start time. That narrows the window; it does not close it |
| User services | `GetUnitByPID` on the system bus resolves a user service to `user@UID.service` rather than the individual unit, so user units are effectively unattestable through this plugin |

**A broker built directly on `SO_PEERPIDFD` plus `sd_pidfd_get_unit()` is race-free, and SPIRE's systemd attestor is not.** Adopting SPIRE for this specific job would mean inheriting a weaker identity mechanism plus a certificate authority, a datastore, a registration-entry lifecycle and a single point of failure.

On footprint, the honest reading is mixed. The "SPIRE is too heavy for a small fleet" sentiment is real but its loudest source is a competitor, so discount it. The neutral observation is that SPIRE's own scaling documentation is written for very large deployments and does not address small-deployment overhead, and that for five hosts the minimum is a server plus one agent per host.

**Revised recommendation:** keep SPIFFE-compatible identity *shapes* so a later migration stays open, but do not adopt SPIRE to solve host-local attestation in the pilot. Round one's instinct to avoid rebuilding identity machinery is right in general and wrong in this particular case.

### 4.2 The baseline the pilot must beat

There is a materially simpler design that solves part of the same problem with no new daemon:

```
systemd-creds encrypt --with-key=host+tpm2   →   /etc/credstore.encrypted/
LoadCredentialEncrypted=  in the unit        →   no broker on the delivery path
```

No socket, no peer authentication, no impersonation surface. Credential names are bound into the ciphertext so they cannot be renamed or repurposed, and material is bound to the machine and installation. The cost is that rotation means re-encrypting and reloading, and there is no approval step and no audit trail.

**For an operator who only wants secrets delivered to Linux services, this wins.** It is free, native, and already installed.

This is not an argument against the product. It is an argument about which half of the product is load-bearing: **the broker earns its existence through approval, brokered operations, and audit, not through credential delivery.** Round one's stopping gate already says that if operators mostly want templated secrets, integrate with an established manager instead. The pilot should make that comparison explicit by running the encrypted-credstore baseline alongside the broker and asking operators which they would keep.

---

## 5. Demand reality check

### 5.1 The practice is arriving, the pain is not yet felt

The most relevant community discussion found is a homelab thread whose author runs "dozens of Linux machines," where **no commenter reports production agent use and credential handling is not discussed at all**. The prevailing sentiment is that hands-off agent fleets are "russian roulette as of today."

Against that, Omarchy 4 ships ten agent command-line tools by default plus a multiplexer that tracks agent state, and Anthropic shipped a self-hosted runner in public beta in August 2026. Typical real deployments run two to five agents behind an orchestrator.

Current credential practice on those hosts is primitive: a `.env` file at mode 600, per-agent scoped tokens, and a vault only among a sophisticated minority.

**The honest framing is that this is a seatbelt being offered in 1958.** The danger is documented, the practice is spreading, and the buyer does not yet believe they have the problem. That is a real risk to adoption timing and it is not solved by better positioning.

### 5.2 The incident record is the strongest part of the case

| Date | Incident | Relevance |
|---|---|---|
| 2026-01-30 | OpenClaw CVE-2026-25253, CVSS 8.8 | WebSocket hijack to token theft to full remote code execution |
| 2026-01 to 2026-03 | Exposed instances grew from 42,665 to 258,305 | Ships with authentication disabled; users put it on always-on VPSes |
| 2026-02-09 | SecurityScorecard: 135,000+ unique IPs, 12,812 remotely exploitable | Scale of unmanaged agent hosts |
| 2026-03-24 | LiteLLM supply-chain compromise | Machines that upgraded that day had environment variables, **SSH keys, cloud credentials, kubeconfigs, database passwords and shell history** exfiltrated |
| 2026-08 | Claude Code and Gemini CLI flaws | A GitHub issue could reach continuous-integration secrets |

What was actually stolen from OpenClaw hosts includes model API keys, bot tokens, and chat histories. **An agent with full user-account access on a Linux box is equivalent to handing an attacker that account.**

### 5.3 The approval feature has been requested by a competitor's users

1Password's own community carries an open feature request for **remote approval for the `op` command-line tool, explicitly to support agentic workflows**. Their desktop approval flow, where each SSH key use raises a prompt approved by biometrics or system authentication, is the closest existing analogue to the proposed interaction, and its documented gap is that it requires a local graphical session.

That is useful validation of the interaction model from outside this project. It is also a warning: the same gap is visible to a vendor with far more distribution, and 1Password's Credential Broker already entered public preview in July 2026.

### 5.4 Approval fatigue is a design constraint, not polish

Multi-factor push bombing is a documented and actively exploited failure mode where users approve prompts to make them stop. An agent broker will generate far more prompts than multi-factor authentication does.

Batching, scoping, and time-bounded grants are therefore **mandatory in the first version**, not later refinements. The pilot should measure approval frequency per operator per day as a primary result, not an incidental one. Round one's validation gate already records approval frequency; it should be promoted to a pass or fail criterion, because a design that produces dozens of prompts a day will be switched off regardless of how sound its cryptography is.

---

## 6. Corrections to round one

| Round one statement | Correction | Source |
|---|---|---|
| The abstract socket name mechanism needs verification against a real implementation | Confirmed, and it is fully documented in `systemd.exec(5)` since v247. Documented as multiplexing, never as authentication | Local test + man page |
| "The caller in this path is the service-manager credential loader" | More precisely, a forked `systemd-executor` child running *before* the service user is enforced. Uid 0 for system units, the session user's uid for user units | Local test + upstream source |
| Reject fabricated names from ordinary clients | Correct, and now demonstrated exploitable. The mechanism must be `SO_PEERPIDFD` plus pidfd-to-unit resolution, with uid 0 required | [Section 1.6](#16-required-broker-authentication-sequence) |
| Same-desktop-UID operation is a "convenience mode with narrower assurances" | Stronger than that: for user-manager units the assurance is **zero**. Any process of that user can impersonate any of that user's units | [Section 1.5](#15-user-scope-units-cannot-be-secured-this-way-at-all) |
| "Changing a broker's value does not refresh a credential already loaded… The service needs an explicit restart" | `RefreshOnReload=` accepts `credentials` and is present in systemd 261, so a `systemctl reload` suffices for opted-in units | `systemd.service(5)` |
| SPIRE "already has Unix UID/GID selectors and systemd unit selectors" | Selectors are `systemd:id` and `systemd:fragment_path`; there is no `systemd:unit`. The attestor is PID-based and racy, and the pidfd fix was declined upstream in June 2026 | SPIRE source and issue 6035 |
| "Evaluate SPIRE as the identity backend before implementing equivalent attestation" | Inverted for this specific job. A direct `SO_PEERPIDFD` implementation is race-free where SPIRE's systemd attestor is not | [Section 4.1](#41-spires-systemd-attestor-is-weaker-than-a-direct-implementation) |
| "TPM support must be detected and fallback behavior made visible" | Correct, and the failure is silent by default. Gate on `systemd-analyze has-tpm2`; note `systemd-creds has-tpm2` is deprecated in 261 | Local check |
| "Market demand among Omarchy users remains untested" | Still true for this product, but the platform is larger than implied: roughly 35,000 stars, 200,000 ISO downloads in 18 days, ten agent tools shipped by default | Desk research |
| "Keep secret values and custody keys out of the plugin" | Correct, and now backed by Omarchy's own documentation, which states plugins are unsandboxed and share the host object tree | Local install |

One addition round one did not have: **a failing broker is fail-open.** systemd has no way for a credential socket to signal absence, so an error yields an empty credential file and the unit starts anyway.

---

## 7. Impact on the pilot test plan

The [pilot test plan](../testing/Native%20Linux%20Fleet%20Pilot.md) is well structured and most scenarios stand. These need revision:

| Scenario | Change required |
|---|---|
| **C01** | Specify the mechanism: require uid 0, resolve the peer through `SO_PEERPIDFD` to a unit and invocation ID, and treat `getpeername()` only as a routing hint validated against that result |
| **C02** | Promote from a hypothesis to a **known exploit with a working reproduction**. The forged-name client in [section 1.3](#13-the-abstract-socket-name-is-trivially-forgeable) should become the regression test verbatim |
| **C04** | Rewrite the expected outcome. systemd will **not** prevent a unit starting with an empty credential, so the requirement moves to the consumer: every credential-consuming service must validate presence and parseability, and the test must prove that validation |
| **C11** | Gate on `systemd-analyze has-tpm2` and assert the **silent** host-key-only downgrade is detected and refused, rather than assuming `auto` reports it |
| **I02** | Already correct in intent. Name `SO_PEERPIDFD` as the required mechanism so the test cannot be satisfied by a `/proc`-parsing implementation |
| **I05** | Correct the selector names to `systemd:id` and `systemd:fragment_path`. Add a case proving the attestor's PID race, since upstream declined to fix it |
| **I04** | Strengthen. The user-scope result means the convenience profile should be documented as providing no isolation for credential sockets, not merely weaker isolation |
| **E08** | Add the `RefreshOnReload=` path as the preferred rotation mechanism, distinct from a full restart |
| **New: C15** | A user-manager unit must be **rejected** by the broker, not served |
| **New: C16** | Run the encrypted-credstore baseline from [section 4.2](#42-the-baseline-the-pilot-must-beat) alongside the broker, and record which one operators would keep |

The `O` series should also add a measurement rather than a pass/fail: **approvals per operator per day**, with a stated threshold above which the design is considered to have failed on usability grounds.

---

## 8. What this changes in the recommendation

**The direction survives this round.** Nothing found invalidates it, and two things strengthen it: the systemd credential-socket integration is genuinely unclaimed by any competitor, and the approval interaction has been independently requested by another vendor's users.

Five adjustments:

1. **Lead with the two defensible claims.** Native systemd credential delivery, and per-request approval bound to attested local process identity. Do not lead with "the agent never holds the credential" — that is now available free from several open-source projects, one with a security-credible maintainer and roughly 3,100 stars.

2. **Build the attestation directly; do not adopt SPIRE for it.** Keep SPIFFE-compatible shapes for a future migration, but the direct pidfd implementation is stronger than the attestor SPIRE ships.

3. **Restrict scope to system units under distinct service accounts.** User-scope credential sockets are unsecurable. This is a documented product boundary, not a pilot shortcut.

4. **Make the Omarchy widget free, open source, and thin.** It is the demonstration surface and the distribution channel, and by the platform's own documentation it cannot hold secrets. Monetize the broker and control plane instead, on the small-fleet curve that Sandfly Security has already validated at around $99 a year for ten hosts.

5. **Treat approval frequency as a first-class result.** Push-bombing fatigue is the most likely cause of quiet abandonment, ahead of any technical failure.

The one genuinely unresolved risk is timing. The incident record proves the danger, but the community evidence shows very few people are yet running the unattended agent fleets this protects. That is a demand-timing risk no amount of engineering resolves, and it is the right thing for the validation gate to measure.

---

## 9. Sources

Verified locally on 2026-09-12 (Omarchy 4.0.3, systemd 261.2, kernel 7.2.3):

- `systemd.exec(5)` `LoadCredential=` and credential socket `getpeername()` semantics
- `systemd.service(5)` `RefreshOnReload=`
- `/usr/share/omarchy/shell/README.md` and `/usr/share/omarchy/shell/services/PluginShellApi.qml` plugin isolation statements
- `/usr/share/omarchy/shell/plugins/agents/` first-party agents module
- Live `SO_PEERPIDFD`, TPM2 and transient-unit credential socket tests

Desk research:

- systemd credentials — <https://systemd.io/CREDENTIALS/>
- Credential socket implementation — <https://raw.githubusercontent.com/systemd/systemd/main/src/core/exec-credential.c>
- Empty-credential fail-open — <https://github.com/systemd/systemd/issues/27373>
- One connection per credential — <https://github.com/systemd/systemd/issues/34223>
- `sd_pid_get_owner_uid(3)` race warning — <https://raw.githubusercontent.com/systemd/systemd/main/man/sd_pid_get_owner_uid.xml>
- `SO_PEERPIDFD` — <https://lwn.net/Articles/926312/>
- Abstract socket permissions — <https://man7.org/linux/man-pages/man7/unix.7.html>
- SPIRE systemd attestor — <https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_systemd.md>
- SPIRE pidfd proposal, closed not-planned — <https://github.com/spiffe/spire/issues/6035>
- Riptides kernel-module approach — <https://riptides.io/blog/when-ebpf-isnt-enough-why-we-went-with-a-kernel-module/>
- Aembit MCP Identity Gateway — <https://docs.aembit.io/ai-guide/mcp/identity-gateway/>
- Teleport workload attestation — <https://goteleport.com/docs/reference/machine-workload-identity/workload-identity/workload-identity-api-and-workload-attestation/>
- 1Password Credential Broker — <https://1password.com/product/credential-broker>
- 1Password remote-approval feature request — <https://www.1password.community/developers-69/feature-request-remote-approval-for-op-cli-desktop-prompts-to-support-agentic-workflows-24119>
- nono agent sandbox and proxy — <https://github.com/nolabs-ai/nono>
- Infisical agent-vault — <https://github.com/Infisical/agent-vault>
- Bitwarden Agent Access SDK — <https://bitwarden.com/blog/introducing-agent-access-sdk/>
- Awesome agent runtime security — <https://github.com/bureado/awesome-agent-runtime-security>
- Tailscale tags and policy — <https://tailscale.com/docs/features/tags>
- Sandfly Security pricing — <https://sandflysecurity.com/get-sandfly>
- Omarchy shell plugins — <https://omarchy.org/manual/shell-plugins/>
- Omarchy Quattro ISO downloads — <https://omarchy.org/news/2026/09/quattro-crosses-200000-iso-downloads/>
- OpenClaw exposure and incidents — <https://www.coral.inc/blog/2026-03-07-openclaw-security-crisis-2026>
- Push-bombing fatigue — <https://securityboulevard.com/2026/07/what-is-mfa-fatigue-push-bombing/>

> **Verification note:** section 1 and the Omarchy isolation findings are first-party observations on this host. Sections 2, 3.1, 3.5, 4 and 5 are desk research with dated sources. Adoption figures from third-party aggregators are directional. System-scope credential socket behaviour is inferred from upstream source and remains untested here.
