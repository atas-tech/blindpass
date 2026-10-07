# Security policy

BlindPass handles secrets for agents and operators, so a report that shows a way to read, redirect, replay or retain one matters more than most bugs. This file says how to report one and what is supported. It does not describe a security guarantee: the [current threat model](docs/security/blindpass-threat-model.md) owns the boundaries, residual risks and what has and has not been verified.

## Supported versions

No release has been published: there are no Git tags, GitHub Releases, registry packages or container images for the Linux fleet pilot, and the packaging, deployment and recovery paths are still under acceptance review. The only supported state is the tip of `main`. A fix lands there; nothing is backported because nothing is released.

This changes with the first release. The release notes will then name the supported versions and the interval during which a fixed release is available. Until that table exists, do not treat any older commit as supported.

## Reporting a vulnerability

Do not open a public issue or pull request that describes a vulnerability, and do not post a working exploit, secret, signed link or token anywhere public.

**Private reporting channel: not established yet.** GitHub private vulnerability reporting is disabled for this repository (checked 2026-10-06) and the repository publishes no security contact. Choosing and publishing one is an owner decision that this file will record once made. Until then, open a public issue that says only that you have a security report and asks for a private channel. Put no details in it.

When a channel exists, include:

- the affected component and commit (controller, broker, node, CLI, console, browser input page, desktop approval app, MCP server, agent skill, gateway, OpenClaw plugin, packaging, or the landing page);
- what an attacker needs (network position, operator account, local access to a host, a stolen link) and what they obtain;
- steps to reproduce against a disposable installation, using generated dummy values. Never send real credentials, keys or customer data.

## Scope

In scope: the Rust controller, host broker, node and CLI; the operator console, browser input page and desktop approval app; the MCP server; the agent skill, gateway and OpenClaw plugin clients while they are retained; the packaging and deployment profiles in `deploy/` and `docs/deploy/`; and the landing page.

The legacy SPS hosted stack (`packages/sps-server`, `packages/dashboard`, Redis and its Unraid templates) was removed on 2026-10-07 and is in git history before the removal commit. It is no longer maintained or supported, and the documents in `docs/legacy/` are archived history.

Outside the guarantees, by design (see the threat model): a recipient runtime or approved process that copies a secret it was legitimately given, a provider credential that outlives its delivery, and a compromised controller host. Report a gap between what the documentation claims and what the software does even when the behavior sits in one of these areas.

## What to expect

A report is acknowledged, assessed against the threat model and answered with whether it is treated as a vulnerability. Fixes ship with a regression test, and the finding is recorded with its status in the repository's security documentation. Credit is given on request. Response times are not yet committed; that is an owner decision recorded here when made.
