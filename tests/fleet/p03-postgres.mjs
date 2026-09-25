// SPDX-License-Identifier: AGPL-3.0-only

import { randomBytes } from 'node:crypto';
import { chmod, readFile, rm, writeFile } from 'node:fs/promises';
import pg from 'pg';

const { Client } = pg;

async function main() {
  const [command, statePath, databaseUrlPath] = process.argv.slice(2);
  if (!statePath) throw new Error('usage: p03-postgres.mjs create STATE_FILE DATABASE_URL_FILE | drop STATE_FILE');
  if (command === 'create') {
    if (!databaseUrlPath) throw new Error('create requires DATABASE_URL_FILE');
    return create(statePath, databaseUrlPath);
  }
  if (command === 'drop') {
    if (!databaseUrlPath) throw new Error('drop requires DATABASE_URL_FILE');
    return drop(statePath, databaseUrlPath);
  }
  throw new Error('command must be create or drop');
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
