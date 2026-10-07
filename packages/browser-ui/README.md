# @blindpass/browser-ui

The secret-input page a person opens from a BlindPass signed link. It shows the request description and confirmation code, encrypts the typed value in the browser with HPKE for the requester's public key and submits the ciphertext once. Vanilla JavaScript under [Decision 0001](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0001-dashboard-ui-stack.md); shared tokens, Inter and icons come from [`assets/ui`](../../assets/ui/ASSETS.md) and strings from `packages/i18n/locales/{en,vi}/browser-ui.json`.

## What the page does and doesn't guarantee

- **Plaintext.** The value exists in the page's input field and in JavaScript memory while it is sealed. The field is cleared on success, on every terminal state (already submitted, no longer available, unavailable, sign-in required, outcome unknown) and when the page is hidden by navigation. The page doesn't store it, log it or put it in a URL. Browser memory erasure isn't claimed. The requester who holds the private key can decrypt and use the value; the copy says so.
- **Exact bytes.** The value is encoded as UTF-8 exactly as typed: nothing is trimmed. Pasting text with line breaks into the single-line field switches to multiline instead of dropping them, and multiline can't be turned off while line breaks remain. Browsers normalise text-area line endings, so Windows CRLF is sent as LF; the multiline help text says this.
- **Scopes.** `metadata_sig` reads the public key, description, code and expiry; `submit_sig` submits. The page never uses an agent token and, for exchange links, sends no cookies (`credentials: "omit"`) or referrer. Fleet links are the one exception, below.
- **API origin.** Fixed at build time by `VITE_BLINDPASS_API_ORIGIN` (or the older `VITE_SPS_API_URL`); empty means the page's own origin, which is the embedded controller build. The signed link's `api_url` parameter is ignored, so a crafted link can't point the page at another server's key.
- **Deadline.** The countdown derives from the metadata `expiry` and the controller's `Date` header, counting the round trip and the header's one-second resolution against the remaining time. Elapsed time is the larger of monotonic and wall-clock time, so a suspended tab can't stretch it; returning to a tab rechecks the deadline and the link. Without a readable `Date` header (a cross-origin controller that doesn't expose it) the page shows the controller's deadline without a countdown.
- **Outcomes.** Success is reported only on the controller's `201` or a status read of `submitted`. `400`, `413` and `429` are definite refusals and keep the value for a corrected retry.
- **Status recovery (CT19).** After metadata loads, the page exchanges `metadata_sig` for a status-only signature (`POST /api/v2/secret/browser-status/{id}/capability`) held in memory, and reads `GET /api/v2/secret/browser-status/{id}`: a request that is already `submitted` opens as "Already submitted". When a submit reply is lost or fails with `5xx`, the field is cleared and the page reads the status once: `submitted` confirms success, `pending` returns to an empty entry field saying nothing was stored, and `410` (consumed, expired or invalid, indistinguishably) or no answer stays "Submission not confirmed" with no claim of failure. Nothing is resubmitted automatically; a manual "Check again" appears only when the status read got no answer. The page never uses an agent token or the agent-authenticated status route.

## States

`loading` → `ready` → `submitting` → `submitted`, or `used` (409), `expired` (410, at load, while open or on submit), `invalid` (incomplete link, 400/403/404; fleet links also an unverifiable offer or a bad capability), `auth` (401, compatibility only; the Rust controller never answers 401 here), `error` (metadata didn't load; retry) and `unknown` (lost or failed submit reply, while checking and when the status can't be learned). See `src/lifecycle.js`.

## Fleet Source links (`kind=fleet`)

The console's "Provide Source" button opens `/?kind=fleet&id=<64 hex>&metadata_sig=<capability>&submit_sig=<capability>` in a new tab. Exchange links (no `kind`) behave as above.

- **Strict link.** Exactly those four parameters, each once, with a 64-character lowercase hex `id` and `<digits>.<43 base64url>` capabilities. Any extra, duplicate, empty or other-`kind` link shows "This link is unavailable" and makes no request.
- **Operator session, same origin only.** The controller binds the link to the approving operator, so fleet mode sends the console session cookie (`credentials: "same-origin"`, `redirect: "error"`) and copies the `bp_csrf` cookie into `x-csrf-token` on submit. It needs the page to be served by the controller (the embedded build, assets under `/input/`) with an empty API origin; a build with a cross-origin API origin refuses fleet links. 401 or 403 shows "Sign in as the named operator" with an "Open console sign-in" link and a "Check again" button; a 403 that names a bad capability shows "unavailable" instead.
- **Verified offer.** Before entry is enabled the page verifies the node's signed offer against the controller's `expected` grant, key version, destination and signing key at the controller's time, and requires the binding's expiry to equal the link's. A failure shows "unavailable"; nothing is encrypted.
- **Deadline.** The countdown starts from `server_time_ms` and `expires_at_ms` in the metadata, counting the round trip and using the larger of monotonic and wall-clock elapsed time. When it ends while the page is open, the field is cleared and nothing is sent.
- **Submit.** The exact UTF-8 bytes (1 to 65 536, nothing trimmed) are sealed with the verified path and posted once as `{enc, ciphertext}` only. `201` or an exact-retry `200` is "submitted"; `409` is "already submitted" (a different ciphertext holds the receipt); `410` and `404` end the link; `400`, `413` and `429` keep the value for a retry; anything else, or a lost reply, is "not confirmed". Then the page reads the link status once: a receipt confirms success, none leaves "Submission not confirmed" with "Check again". It never resubmits on its own.
- **Clearing.** The field is cleared on success, on every terminal state, when the page is hidden while ready, and on `pagehide`.
- **Capabilities stay in the address bar.** The controller serves this page at `/` only when `id`, `metadata_sig` and `submit_sig` are all present, and reload recovery depends on them, so they are not stripped. They are short-lived, scoped and useless without the named operator's session; the server sets `Referrer-Policy: no-referrer`.

Checks: `npm test --workspace=@blindpass/browser-ui` covers strict parsing, the server-time deadline, outcome mapping, the verified-offer and real-HPKE round trip (`tests/fleet-flow.test.mjs`) and source guards (`tests/fleet-page-source.test.mjs`: no `sealBrowserSource`, credentials only in fleet mode, no storage, logging or history use, CSP rules). The end-to-end journeys are in `packages/console/e2e/provisioning.spec.ts` against the real controller with a JavaScript node fixture instead of a broker; see [UI evidence](../../docs/testing/evidence/p05-provisioning-ui-2026-10-02.md). Not established: a real broker or node process, real tab switching or back/forward-cache restores (hidden-page clearing is tested by dispatching the events), an Omarchy or desktop session, and hosted CI.

## Security headers

Builds inject a CSP meta tag: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' <API origin>; base-uri 'none'; form-action 'self'`. `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy`, `Referrer-Policy: no-referrer` and `Permissions-Policy` must come from the server: `vite preview`, the packaged [nginx.conf.template](nginx.conf.template) (its `connect-src` is rendered at image build from `VITE_SPS_API_URL` by `scripts/render-nginx-conf.mjs`, which refuses loopback, plain-http, wildcard or path-bearing origins unless `BLINDPASS_UI_DEV_IMAGE=1`) and, from P04 slice 13, the controller. There is no inline script or style.

## Development and tests

### Fleet provisioning contract preparation — 2026-10-02

The separate [fleet helper](src/fleet-provisioning.js) validates a versioned
browser-source binding and seals exact UTF-8 bytes with domain-separated
canonical metadata as HPKE additional authenticated data. It binds the full
browser grant, original operation/invocation/resource, current node key version,
ephemeral offer key/ID, fixed source unit/credential and original capped deadline.
The existing exchange page retains its empty-AAD contract.

`verifyBrowserRecipientOffer` verifies a native signed offer against independently
trusted enrollment and authorized operation/destination data.
`sealVerifiedBrowserSource` verifies before sealing; the page's fleet mode uses
only this verified path (never `sealBrowserSource`) and passes the controller's
time, not the page clock (see "Fleet Source links" below). A real broker's offer
creation and one-use broker custody are not exercised by this package's tests.
Metadata equality or browser clock validation cannot establish grant authority.
The receiver must independently recheck current authority and original deadlines.

The plaintext string remains in caller/browser memory. The temporary encoded
buffer is wiped after sealing; JavaScript strings have no forensic erasure
guarantee. Only ciphertext/encapsulation are returned, with fixed error messages.
Credential bytes are nonempty and bounded64KiB. No value is trimmed or logged.

Five browser-library cases, four Rust contract cases and seven actual
browser-library-to-Rust interoperability cases pass. The latter run on both
pinned Node profiles and verify exact canonical bytes, valid decryption, changed
destination/operation/offer/recipient, legacy empty AAD and truncation denial.
These are crypto/component tests, without a real operator UI or fleet admission.
See [provisioning evidence](../../docs/testing/evidence/p05-provisioning-2026-10-02.md).
The later [signed-offer evidence](../../docs/testing/evidence/p05-signed-offer-2026-10-02.md)
adds three core/three browser signature cases, eight actual native-signature
exchanges and one sandboxed Chromium crypto case per pinned Node profile.

### Existing input page checks

```bash
npm test --workspace=@blindpass/browser-ui          # unit tests: state machine, deadline, exact bytes, HPKE round trip, size limit
VITE_BLINDPASS_API_ORIGIN=http://127.0.0.1:3100 npm run dev --workspace=@blindpass/browser-ui
npx playwright test e2e/input.spec.ts                # from packages/console: SI and P04-E03 scenarios against the Rust controller
```

There is no preview mode: without a complete signed link the page shows "This link is unavailable" and makes no request.
