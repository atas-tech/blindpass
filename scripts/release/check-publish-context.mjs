// SPDX-License-Identifier: AGPL-3.0-only
// P07-D3: "prepublishOnly" guard. Publication belongs to the approved release workflow
// (.github/workflows/release.yml, environment release-approval); a developer-machine
// `npm publish` from the source directory stops here. This is a guard against accidents, not
// against someone who edits the environment: the npm-side control is publishConfig.provenance,
// which makes npm refuse to publish outside a supported CI identity. Note that npm does not run lifecycle
// scripts when publishing a tarball; the workflow publishes the staged tarball under provenance.
const env = process.env;
const expected = {
  GITHUB_ACTIONS: (v) => v === 'true',
  GITHUB_WORKFLOW: (v) => v === 'Release',
  GITHUB_REPOSITORY: (v) => v === 'atas-tech/blindpass',
  GITHUB_REF: (v) => /^refs\/tags\/v\d+\.\d+\.\d+$/.test(v ?? ''),
  BLINDPASS_RELEASE_APPROVED: (v) => v === '1',
};
const wrong = Object.entries(expected).filter(([name, ok]) => !ok(env[name])).map(([name]) => name);
if (wrong.length > 0) {
  console.error('refusing to publish: this package is published only by the approved Release workflow for a vX.Y.Z tag.');
  console.error(`context check failed for: ${wrong.join(', ')}`);
  process.exit(1);
}
