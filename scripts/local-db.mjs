// Local PostgreSQL 17 without Docker (embedded-postgres), separate from CampusHub's clusters: one cluster on :5434
// with the databases "sentinel" (dev) and "sentinel_test" (tests), user/password sentinel/sentinel. The server keeps
// running in the background after this script exits; `node scripts/local-db.mjs stop` stops it.
import EmbeddedPostgres from 'embedded-postgres';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 5434;
const DIR = path.join(root, '.localdb', 'cluster');
const USER = 'sentinel';
const PASSWORD = 'sentinel';
const DATABASES = ['sentinel', 'sentinel_test'];

async function canConnect(database = 'postgres') {
  const c = new pg.Client({ host: 'localhost', port: PORT, user: USER, password: PASSWORD, database, connectionTimeoutMillis: 1500 });
  try {
    await c.connect();
    await c.end();
    return true;
  } catch {
    return false;
  }
}

// pg_ctl starts a detached server that outlives this script (embedded-postgres' own start() is a child process).
function pgCtl() {
  const pkg = {
    win32: '@embedded-postgres/windows-x64',
    darwin: process.arch === 'arm64' ? '@embedded-postgres/darwin-arm64' : '@embedded-postgres/darwin-x64',
    linux: process.arch === 'arm64' ? '@embedded-postgres/linux-arm64' : '@embedded-postgres/linux-x64',
  }[process.platform];
  return path.join(root, 'node_modules', pkg, 'native', 'bin', process.platform === 'win32' ? 'pg_ctl.exe' : 'pg_ctl');
}

async function start() {
  if (await canConnect()) {
    console.log(`[db] cluster already running on :${PORT}`);
  } else {
    if (!fs.existsSync(path.join(DIR, 'PG_VERSION'))) {
      console.log(`[db] initialising cluster in ${path.relative(root, DIR)} …`);
      await new EmbeddedPostgres({
        databaseDir: DIR,
        user: USER,
        password: PASSWORD,
        port: PORT,
        persistent: true,
        initdbFlags: ['--encoding=UTF8', '--locale=C'],
        onLog: () => {},
        onError: (e) => process.env.LOCALDB_VERBOSE && console.error(String(e)),
      }).initialise();
    }
    const pid = path.join(DIR, 'postmaster.pid');
    if (fs.existsSync(pid)) fs.rmSync(pid); // stale after an unclean shutdown (the port is free)
    execFileSync(pgCtl(), ['-D', DIR, '-l', path.join(DIR, 'server.log'), '-o', `-p ${PORT}`, '-w', 'start'], { stdio: 'ignore' });
    console.log(`[db] cluster started on :${PORT}`);
  }
  const admin = new pg.Client({ host: 'localhost', port: PORT, user: USER, password: PASSWORD, database: 'postgres' });
  await admin.connect();
  for (const db of DATABASES) {
    const exists = await admin.query('select 1 from pg_database where datname = $1', [db]);
    if (exists.rowCount === 0) {
      await admin.query(`create database ${db}`);
      console.log(`[db] created database ${db}`);
    }
  }
  await admin.end();
}

async function stop() {
  if (!(await canConnect())) return console.log('[db] cluster is not running');
  execFileSync(pgCtl(), ['-D', DIR, '-m', 'fast', '-w', 'stop'], { stdio: 'ignore' });
  console.log('[db] cluster stopped');
}

try {
  await (process.argv[2] === 'stop' ? stop() : start());
  if (process.argv[2] !== 'stop') console.log(`[db] ready: postgresql://${USER}:${PASSWORD}@localhost:${PORT}/sentinel (tests: /sentinel_test)`);
  process.exit(0);
} catch (err) {
  console.error('[db] failed:', err?.message ?? err);
  process.exit(1);
}
