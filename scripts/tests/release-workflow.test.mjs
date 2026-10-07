// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2/P07.6 static policy for .github/workflows/release.yml. actionlint is not available on the
// maintainer machine, so these checks pin the properties that matter for a workflow that cannot be
// run locally. They do not prove the workflow executes; the first hosted run does.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FILE = path.join(ROOT, '.github/workflows/release.yml');
const SOURCE = await readFile(FILE, 'utf8');

const parsed = spawnSync('python3', ['-c', 'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))', FILE], { encoding: 'utf8' });
const noYaml = parsed.status !== 0 && /No module named 'yaml'/.test(parsed.stderr);
const skip = noYaml && 'PyYAML unavailable';
const workflow = parsed.status === 0 ? JSON.parse(parsed.stdout) : undefined;
const jobs = workflow?.jobs ?? {};
const triggers = workflow?.on ?? workflow?.true ?? {};
const steps = (job) => job.steps ?? [];
const runText = (job) => steps(job).map((s) => s.run ?? '').join('\n');
const jobText = (job) => JSON.stringify(job);

test('P07-D2: the workflow parses and is named Release (the publish guard checks this name)', { skip }, () => {
  assert.equal(parsed.status, 0, parsed.stderr);
  assert.equal(workflow.name, 'Release');
});

test('P07-D2: it runs only on version tags and manual dispatch, never on pull requests', { skip }, () => {
  assert.deepEqual(Object.keys(triggers).sort(), ['push', 'workflow_dispatch']);
  assert.deepEqual(triggers.push.tags, ['v[0-9]+.[0-9]+.[0-9]+']);
  assert.equal(triggers.push.branches, undefined);
  assert.ok(!/pull_request/.test(SOURCE.replace(/^\s*#.*$/gm, '')));
});

test('P07-D2: default token is read-only and every job has a timeout', { skip }, () => {
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  for (const [name, job] of Object.entries(jobs)) assert.ok(Number.isInteger(job['timeout-minutes']), `${name} has no timeout-minutes`);
});

test('P07-D2: every third-party action is pinned to a full commit SHA', { skip }, () => {
  const uses = [...SOURCE.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)].map((m) => m[1]);
  assert.ok(uses.length > 0);
  for (const use of uses) assert.match(use, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/, `${use} is not SHA-pinned`);
});

test('P07.6: only jobs behind the release-approval environment can publish', { skip }, () => {
  const publishing = /skopeo copy[^\n]*docker:\/\/|npm publish|gh release edit|docker push|--draft=false/;
  const gated = Object.entries(jobs).filter(([, job]) => job.environment === 'release-approval').map(([name]) => name).sort();
  assert.deepEqual(gated, ['publish-image', 'publish-npm', 'publish-release']);
  for (const [name, job] of Object.entries(jobs)) {
    if (job.environment === 'release-approval') {
      assert.equal(job.if, "github.ref_type == 'tag'", `${name} must run only for tags`);
      assert.ok(/check-publish-gate\.sh/.test(runText(job)), `${name} does not run the evidence gate`);
      assert.ok(/verify\.sh/.test(runText(job)), `${name} does not verify the signed candidate`);
    } else {
      assert.ok(!publishing.test(runText(job)), `${name} publishes without the approval environment`);
      for (const permission of ['packages', 'id-token']) assert.notEqual(job.permissions?.[permission], 'write', `${name} has ${permission}: write without approval`);
    }
  }
  // The only unapproved writer is the draft staging job, and it can only create drafts.
  const draft = jobs['draft-release'];
  assert.equal(draft.permissions.contents, 'write');
  assert.ok(/gh release create[^\n]*--draft/.test(runText(draft)));
  assert.ok(!/--draft=false|release edit/.test(runText(draft)));
  for (const [name, job] of Object.entries(jobs)) {
    if (name !== 'draft-release' && job.environment !== 'release-approval') assert.notEqual(job.permissions?.contents, 'write', `${name} can write contents`);
  }
});

test('P07.6: publication needs the staged, verified candidate and ordered jobs', { skip }, () => {
  const needs = (name) => [].concat(jobs[name].needs ?? []);
  for (const name of ['publish-image', 'publish-npm']) {
    assert.ok(needs(name).includes('verify-candidate') && needs(name).includes('draft-release'), `${name} does not wait for the verified draft`);
  }
  for (const dependency of ['draft-release', 'publish-image', 'publish-npm']) assert.ok(needs('publish-release').includes(dependency), `publish-release does not wait for ${dependency}`);
  assert.ok(needs('draft-release').includes('verify-candidate'));
  assert.ok(needs('verify-candidate').includes('assemble-and-sign'));
  assert.ok(/skopeo copy[^\n]*--all[^\n]*--preserve-digests[^\n]*oci-archive:/.test(runText(jobs['publish-image'])), 'image must be pushed from the staged OCI archive with its digests');
  assert.ok(/npm publish "?candidate\/[^\n]*\.tgz[^\n]*--provenance/.test(runText(jobs['publish-npm'])), 'npm must publish the staged tarball under provenance');
  assert.equal(jobs['publish-npm'].permissions['id-token'], 'write');
  assert.ok(/check-publish-context\.mjs/.test(runText(jobs['publish-npm'])));
  assert.ok(/--draft=false/.test(runText(jobs['publish-release'])));
});

test('P07-D2: the signing key and registry token are scoped to the one job that needs each', { skip }, () => {
  const holders = (secret) => Object.entries(jobs).filter(([, job]) => jobText(job).includes(secret)).map(([name]) => name);
  assert.deepEqual(holders('RELEASE_SIGNING_KEY'), ['assemble-and-sign']);
  assert.equal(jobs['assemble-and-sign'].environment, 'release-signing');
  assert.deepEqual(holders('NPM_TOKEN'), ['publish-npm']);
  const text = runText(jobs['assemble-and-sign']);
  assert.ok(/umask 077/.test(text) && /sign\.sh --key/.test(text));
  assert.ok(!/echo[^\n]*RELEASE_SIGNING_KEY|set -x|xtrace/.test(text));
  assert.ok(steps(jobs['assemble-and-sign']).some((s) => s.if === 'always()' && /shred|rm -f/.test(s.run ?? '') && /release_signing_key/.test(s.run ?? '')), 'key file is not removed on failure');
  assert.deepEqual(Object.keys(jobs['assemble-and-sign'].permissions ?? { contents: 'read' }), ['contents']);
});

test('P07-D3: the npm job builds, stages, packs and verifies the esbuild bundle, not the workspace library', { skip }, () => {
  const npm = runText(jobs['npm-package']);
  assert.ok(!/--workspace=@blindpass\/mcp-server(?!-lib)|mcp-package\.test/.test(npm), 'the npm job still targets the old library package');
  assert.ok(/npm run build --workspace=@blindpass\/mcp-server-lib/.test(npm) && /npm test --workspace=@blindpass\/mcp-server-lib/.test(npm), 'the library is no longer built and tested');
  assert.ok(/scripts\/build_bundle\.sh/.test(npm), 'the bundle is not built from the exact commit');
  assert.ok(/scripts\/publish_dist\.sh --skip-build --skip-validate --stage-dir/.test(npm), 'the stage is not made by publish_dist.sh');
  assert.ok(/npm pack --pack-destination/.test(npm), 'the stage is not packed (the prepack guard must run)');
  assert.ok(/mcp-bundle-package\.test\.mjs/.test(npm) && /mcp-bundle-notices\.test\.mjs/.test(npm));
  assert.ok(/verify-npm-candidate\.mjs[\s\S]*?--sbom/.test(npm));
  assert.ok(!/--require-lock-identical/.test(npm + runText(jobs['verify-candidate'])), 'a bundle has no dependency tree to compare with the lockfile');
  assert.ok(!/npm publish/.test(npm), 'staging must not publish');
});

test('P07-D3: the source job reads the release version from the packages that carry it, not from the private library', { skip }, () => {
  const text = runText(jobs.source);
  assert.ok(!/packages\/mcp-server\/package\.json/.test(text), 'the version is still read from the library manifest');
  for (const file of ['SKILL.md', 'openclaw.plugin.json']) assert.ok(text.includes(file), `${file} is not cross-checked`);
  assert.ok(/does not match|differs/.test(text));
});

test('P07-D2: the independent fingerprint comes from a repository variable, not the checkout', { skip }, () => {
  for (const name of ['assemble-and-sign', 'verify-candidate', 'publish-image', 'publish-npm', 'publish-release']) {
    const job = jobs[name];
    const refs = steps(job).filter((s) => /verify\.sh/.test(s.run ?? ''));
    assert.ok(refs.length > 0, `${name} never verifies`);
    for (const step of refs) {
      assert.ok(/--fingerprint "\$RELEASE_KEY_FINGERPRINT"/.test(step.run), `${name}: verify.sh without the pinned fingerprint`);
      assert.match((step.env ?? job.env)?.RELEASE_KEY_FINGERPRINT ?? '', /^\$\{\{ vars\.RELEASE_KEY_FINGERPRINT \}\}$/);
    }
  }
});

test('P07-D2: run blocks interpolate no untrusted expressions and the build probes no live endpoint', { skip }, () => {
  const allowed = /\$\{\{\s*(?:runner\.temp|matrix\.(?:arch|runner|node)|needs\.source\.outputs\.version)\s*\}\}/g;
  for (const [name, job] of Object.entries(jobs)) {
    const text = runText(job).replace(allowed, '');
    assert.ok(!text.includes('${{'), `${name}: expression interpolated into a shell script`);
  }
  assert.ok(!/blindpass\.dev|atas\.tech\/|sps\.atas|\bcurl\b|\bwget\b/.test(Object.values(jobs).map(runText).join('\n')), 'a build step reaches a product endpoint or downloads with curl/wget');
});

test('P07-D2: the controller image keeps the reviewed scanner pin and is exported, not pushed, at staging', { skip }, () => {
  const text = runText(jobs.image);
  assert.ok(text.includes('docker/buildkit-syft-scanner:stable-1@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9'));
  assert.ok(text.includes('SELECT_CATALOGERS=+sbom-cataloger,+rust-cargo-lock-cataloger,+javascript-package-cataloger,+dpkg-db-cataloger'));
  assert.ok(/--output type=oci,dest=/.test(text));
  assert.ok(!/--push|--load|push=true/.test(text));
  assert.ok(/controller-sbom\.py --archive/.test(text) && /extract-image-sbom\.py/.test(text));
  assert.match(text, /image=moby\/buildkit:buildx-stable-1@sha256:[0-9a-f]{64}/);
});

test('P07-slice7: the image job derives the docker-load archive from the verified OCI archive, so a stock Docker can load the release', { skip }, () => {
  // Found by the dry run: `docker load` refuses the OCI archive on the default overlay2 store.
  const text = runText(jobs.image);
  assert.ok(/oci-to-docker-archive\.py[\s\\]+--archive/.test(text), 'the docker archive is converted from the OCI archive');
  assert.ok(/blindpass-controller-image-"\$VERSION"-linux-amd64\.docker\.tar/.test(text), 'the asset has the inventory name');
  assert.ok(text.indexOf('extract-image-sbom.py') < text.indexOf('oci-to-docker-archive.py'), 'conversion happens only after the archive is verified');
  assert.ok(/--tag "\$IMAGE_REPOSITORY:\$VERSION"/.test(text.slice(text.indexOf('oci-to-docker-archive.py'))), 'the converted archive carries the release tag');
});

test('P07-D2: the image build is named, because BuildKit leaves the attestation subject empty for an unnamed image', { skip }, () => {
  // Found by the P07 dry-run environment: `--output type=oci,dest=` with no --tag produces in-toto
  // statements whose `subject` is empty, so controller-sbom.py and extract-image-sbom.py both refuse
  // the archive ("wrong attestation subject"). The same build with --tag passes both.
  const text = runText(jobs.image);
  assert.ok(/--tag "\$IMAGE_REPOSITORY:\$VERSION"/.test(text), 'the buildx build must carry --tag "$IMAGE_REPOSITORY:$VERSION"');
  assert.ok(text.indexOf('--tag') < text.indexOf('--output type=oci'), 'the tag belongs to the same buildx invocation as the OCI output');
});

test('P07-D2: the candidate is assembled by the tested scripts, not by ad-hoc commands', { skip }, () => {
  const text = runText(jobs['assemble-and-sign']);
  for (const script of ['render-pkgbuild.sh', 'make-sums.sh', 'sign.sh', 'verify.sh']) assert.ok(text.includes(script), `${script} not used`);
  assert.ok(/--check-dir candidate/.test(text));
  assert.ok(/tamper/i.test(runText(jobs['verify-candidate'])) && /verify-npm-candidate\.mjs/.test(runText(jobs['verify-candidate'])));
  assert.deepEqual(jobs['verify-candidate'].strategy.matrix.node, ['24.21.0', '26.10.0']);
});

// P07-I04, owner decision 6 (applied pending confirmation): the 7 GB test-only toolkit image carries test
// keys and the repository source by design, so the exposure gate does not scan it. That is only sound while
// nothing that publishes, releases or deploys can build, push or run it; the one place that may name it is
// the Dockerfile stage that defines it.
test('P07-I04: no workflow, release script or deployment file builds, pushes or runs the test-only pgtest image', async () => {
  const { readdir } = await import('node:fs/promises');
  const found = [];
  async function walk(directory) {
    for (const entry of await readdir(path.join(ROOT, directory), { withFileTypes: true })) {
      const relative = path.posix.join(directory, entry.name);
      if (entry.isDirectory()) await walk(relative);
      else if (/pgtest/.test(await readFile(path.join(ROOT, relative), 'utf8'))) found.push(relative);
    }
  }
  for (const directory of ['.github/workflows', 'scripts/release', 'deploy']) await walk(directory);
  assert.deepEqual(found.sort(), ['deploy/controller/Dockerfile']);
});
