# @blindpass/browser-ui

The secret-input page a person opens from a BlindPass signed link. It shows the request description and confirmation code, encrypts the typed value in the browser with HPKE for the requester's public key and submits the ciphertext once. Vanilla JavaScript under [Decision 0001](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0001-dashboard-ui-stack.md); shared tokens, Inter and icons come from [`assets/ui`](../../assets/ui/ASSETS.md) and strings from `packages/i18n/locales/{en,vi}/browser-ui.json`.

## What the page does and doesn't guarantee

- **Plaintext.** The value exists in the page's input field and in JavaScript memory while it is sealed. The field is cleared on success, on every terminal state (already submitted, no longer available, unavailable, sign-in required, outcome unknown) and when the page is hidden by navigation. The page doesn't store it, log it or put it in a URL. Browser memory erasure isn't claimed. The requester who holds the private key can decrypt and use the value; the copy says so.
- **Exact bytes.** The value is encoded as UTF-8 exactly as typed: nothing is trimmed. Pasting text with line breaks into the single-line field switches to multiline instead of dropping them, and multiline can't be turned off while line breaks remain. Browsers normalise text-area line endings, so Windows CRLF is sent as LF; the multiline help text says this.
- **Scopes.** `metadata_sig` reads the public key, description, code and expiry; `submit_sig` submits. The page never uses an agent token and sends no cookies (`credentials: "omit"`) or referrer.
- **API origin.** Fixed at build time by `VITE_BLINDPASS_API_ORIGIN` (or the older `VITE_SPS_API_URL`); empty means the page's own origin, which is the embedded controller build. The signed link's `api_url` parameter is ignored, so a crafted link can't point the page at another server's key.
- **Deadline.** The countdown derives from the metadata `expiry` and the controller's `Date` header, counting the round trip and the header's one-second resolution against the remaining time. Elapsed time is the larger of monotonic and wall-clock time, so a suspended tab can't stretch it; returning to a tab rechecks the deadline and the link. Without a readable `Date` header (a cross-origin controller that doesn't expose it) the page shows the controller's deadline without a countdown.
- **Outcomes.** Success is reported only on the controller's `201` or a status read of `submitted`. `400`, `413` and `429` are definite refusals and keep the value for a corrected retry.
- **Status recovery (CT19).** After metadata loads, the page exchanges `metadata_sig` for a status-only signature (`POST /api/v2/secret/browser-status/{id}/capability`) held in memory, and reads `GET /api/v2/secret/browser-status/{id}`: a request that is already `submitted` opens as "Already submitted". When a submit reply is lost or fails with `5xx`, the field is cleared and the page reads the status once: `submitted` confirms success, `pending` returns to an empty entry field saying nothing was stored, and `410` (consumed, expired or invalid, indistinguishably) or no answer stays "Submission not confirmed" with no claim of failure. Nothing is resubmitted automatically; a manual "Check again" appears only when the status read got no answer. The page never uses an agent token or the agent-authenticated status route.

## States

`loading` → `ready` → `submitting` → `submitted`, or `used` (409), `expired` (410, at load, while open or on submit), `invalid` (incomplete link, 400/403/404), `auth` (401, compatibility only; the Rust controller never answers 401 here), `error` (metadata didn't load; retry) and `unknown` (lost or failed submit reply, while checking and when the status can't be learned). See `src/lifecycle.js`.

## Security headers

Builds inject a CSP meta tag: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' <API origin>; base-uri 'none'; form-action 'self'`. `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy`, `Referrer-Policy: no-referrer` and `Permissions-Policy` must come from the server: `vite preview`, the packaged [nginx.conf](nginx.conf) and, from P04 slice 13, the controller. There is no inline script or style.

## Development and tests

```bash
npm test --workspace=@blindpass/browser-ui          # unit tests: state machine, deadline, exact bytes, HPKE round trip, size limit
VITE_BLINDPASS_API_ORIGIN=http://127.0.0.1:3100 npm run dev --workspace=@blindpass/browser-ui
npx playwright test e2e/input.spec.ts                # from packages/console: SI and P04-E03 scenarios against the Rust controller
```

There is no preview mode: without a complete signed link the page shows "This link is unavailable" and makes no request.
