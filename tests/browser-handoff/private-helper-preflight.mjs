// SPDX-License-Identifier: AGPL-3.0-only
// No credentials, links or sessions are present in this public runtime probe.
import { chromium } from '/usr/lib/blindpass/login/node_modules/playwright/index.mjs';
try {
  const browser = await chromium.launch({ headless: true, chromiumSandbox: true, timeout: 10_000 });
  console.log(`P05-HELPER-PREFLIGHT sandbox=enabled browser=${browser.version()}`);
  await browser.close();
} catch (error) {
  const source = typeof error.message === 'string' ? error.message : '';
  const category = source.includes('error while loading shared libraries') ? 'missing_shared_library'
    : /No usable sandbox|Failed to move to new namespace|Operation not permitted|unprivileged_userns|Permission denied/.test(source) ? 'sandbox_or_permission_denied'
      : source.includes('Executable doesn') ? 'missing_browser_binary' : 'runtime_failure';
  console.log(`P05-HELPER-PREFLIGHT failure=${category}`);
  const hints = source.match(/(?:No usable sandbox|Failed to move to new namespace|Permission denied|Operation not permitted)[^\n]{0,180}/g) ?? [];
  console.log(JSON.stringify({ publicSandboxHints: hints }));
  process.exitCode = 1;
}
