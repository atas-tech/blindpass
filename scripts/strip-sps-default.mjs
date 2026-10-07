// SPDX-License-Identifier: AGPL-3.0-only
// P07 F-3: copy the plugin manifest for the PUBLISHED bundle with no default SPS endpoint.
//
//   node scripts/strip-sps-default.mjs <source manifest> <output manifest>
//
// The source manifest belongs to the unbundled OpenClaw plugin and keeps its default. The bundle copy drops
// `configSchema.properties.SPS_BASE_URL.default` and the example host in the description, so the published
// package names no built-in SPS host anywhere.
import { readFileSync, writeFileSync } from 'node:fs';

const [source, output] = process.argv.slice(2);
if (!source || !output) {
  console.error('usage: strip-sps-default.mjs <source manifest> <output manifest>');
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(source, 'utf8'));
const setting = manifest.configSchema?.properties?.SPS_BASE_URL;
if (!setting || typeof setting !== 'object') {
  console.error(`[blindpass] ${source} no longer declares configSchema.properties.SPS_BASE_URL`);
  process.exit(1);
}
delete setting.default;
setting.description = 'Base URL of the Secret Provisioning Service (required for the SPS tools; there is no default endpoint)';

const text = `${JSON.stringify(manifest, null, 4)}\n`;
if (/sps\.blindpass\.dev/.test(text)) {
  console.error('[blindpass] the bundle manifest still names the legacy SPS host');
  process.exit(1);
}
writeFileSync(output, text);
