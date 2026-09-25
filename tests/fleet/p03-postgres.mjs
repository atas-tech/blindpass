// SPDX-License-Identifier: AGPL-3.0-only

import { randomBytes } from 'node:crypto';
import { chmod, readFile, rm, writeFile } from 'node:fs/promises';
import pg from 'pg';

const { Client } = pg;

async function main() {
  const [command, firstPath, secondPath, ...extra] = process.argv.slice(2);
  if (!firstPath) throw new Error('usage: p03-postgres.mjs create STATE_FILE DATABASE_URL_FILE | drop STATE_FILE DATABASE_URL_FILE | grant-acknowledged DATABASE_URL_FILE NODE_ID GRANT_ID');
  if (command === 'create') {
    if (!secondPath) throw new Error('create requires DATABASE_URL_FILE');
    return create(firstPath, secondPath);
  }
  if (command === 'drop') {
    if (!secondPath) throw new Error('drop requires DATABASE_URL_FILE');
    return drop(firstPath, secondPath);
  }
  if (command === 'grant-acknowledged') {
    if (!secondPath || !extra[0] || extra.length !== 1) {
      throw new Error('grant-acknowledged requires DATABASE_URL_FILE NODE_ID GRANT_ID');
    }
    return grantAcknowledged(firstPath, secondPath, extra[0]);
  }
  throw new Error('command must be create, drop or grant-acknowledged');
}

async function grantAcknowledged(databaseUrlPath, nodeId, grantId) {
  const connectionString = (await readFile(databaseUrlPath, 'utf8')).trim();
  const client = new Client({ connectionString });
  await client.connect();
  try {
    const { rows } = await client.query(
      'SELECT envelope_json FROM node_inbox WHERE node_id = $1 AND acked_at IS NOT NULL',
      [nodeId],
    );
    const acknowledged = rows.some(({ envelope_json }) => {
      try {
        const envelope = JSON.parse(envelope_json);
        return envelope.kind === 'grant' && envelope.body?.id === grantId;
      } catch {
        return false;
      }
    });
    process.stdout.write(`${acknowledged}\n`);
  } finally {
    await client.end();
  }
}

async function create(statePath, databaseUrlPath) {
  const parentUrl = process.env.P03_TEST_POSTGRES_URL;
  if (!parentUrl) throw new Error('P03_TEST_POSTGRES_URL is required for PostgreSQL runs');
  const schema = `blindpass_p03_${process.pid}_${randomBytes(6).toString('hex')}`;
  const client = new Client({ connectionString: parentUrl });
  await client.connect();
  try {
    await client.query(`CREATE SCHEMA "${schema}"`);
  } finally {
    await client.end();
  }
  const scopedUrl = new URL(parentUrl);
  scopedUrl.searchParams.set('options', `-c search_path=${schema}`);
  const state = { schema, parentUrl, scopedUrl: scopedUrl.toString() };
  await writeFile(statePath, JSON.stringify(state), { flag: 'wx', mode: 0o600 });
  await chmod(statePath, 0o600);
  await writeFile(databaseUrlPath, `${state.scopedUrl}\n`, { flag: 'wx', mode: 0o600 });
  await chmod(databaseUrlPath, 0o600);
}

async function drop(statePath, databaseUrlPath) {
  const state = JSON.parse(await readFile(statePath, 'utf8'));
  if (!/^blindpass_p03_[0-9]+_[a-f0-9]{12}$/.test(state.schema)) {
    throw new Error('isolated PostgreSQL schema marker is invalid');
  }
  const client = new Client({ connectionString: state.parentUrl });
  await client.connect();
  try {
    await client.query(`DROP SCHEMA IF EXISTS "${state.schema}" CASCADE`);
  } finally {
    await client.end();
  }
  await rm(statePath, { force: true });
  await rm(databaseUrlPath, { force: true });
}

main().catch(() => {
  process.stderr.write('p03-postgres: isolated schema operation failed\n');
  process.exitCode = 1;
});
