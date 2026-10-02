// SPDX-License-Identifier: AGPL-3.0-only
export function guestBrowserProfile(kind = 'fixture') {
  if (kind === 'fixture') return Object.freeze({ kind, reportPath: '/reports', replayPath: '/reports', cookieNames: Object.freeze(['__Host-bp-fixture']) });
  if (kind === 'grafana-managed') return Object.freeze({ kind, reportPath: '/d/p05-primary', replayPath: '/api/user', cookieNames: Object.freeze(['grafana_session', 'grafana_session_expiry']) });
  throw new Error('guest_browser_profile_invalid');
}

// Only the private Root scanner receives these copyable website session bytes.
// No cookie or upstream text is reflected in failure diagnostics.
export function copiedSession(text, profile) {
  try {
    if (typeof text !== 'string' || text.length > 65536) throw new Error();
    return profile.cookieNames.map(name => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const matches = [...text.matchAll(new RegExp(`(?<![A-Za-z0-9_-])${escaped}=([A-Za-z0-9_.-]{1,2048})(?=[;\\s"\\\\]|$)`, 'g'))];
      if (matches.length !== 1) throw new Error();
      return `${name}=${matches[0][1]}`;
    }).join('; ');
  } catch { throw new Error('guest_session_invalid'); }
}

export function decodeBootstrapReply(bytes) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length < 6 || bytes.length > 16388 || bytes.readUInt32BE() !== bytes.length - 4) throw new Error();
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(4)));
    if (value.status !== 'authenticated' || !Number.isSafeInteger(value.revokeHandle?.userId) || value.revokeHandle.userId < 1 || !Array.isArray(value.cookies)) throw new Error();
    return value;
  } catch { throw new Error('guest_bootstrap_failed'); }
}

export function reportSteps(profile, origin) {
  try {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin) throw new Error();
    const selected = guestBrowserProfile(profile.kind);
    return [
      { name: 'browser_navigate', arguments: { url: origin + selected.reportPath } },
      ...(selected.kind === 'grafana-managed' ? [{ name: 'browser_wait_for', arguments: { text: 'Coordinator report: 12 artifacts' } }] : []),
      { name: 'browser_snapshot', arguments: {} },
    ];
  } catch { throw new Error('guest_browser_profile_invalid'); }
}
