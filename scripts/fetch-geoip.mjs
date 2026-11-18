// Downloads the free DB-IP Lite database (CC BY 4.0, https://db-ip.com) used to place visitors on a map without
// sending their IP addresses to any third party. Run at build time (Render) and once locally:
//   node scripts/fetch-geoip.mjs [country|city]      (default: GEOIP_EDITION or country)
// Writes backend/.geoip/dbip-<edition>-lite.mmdb (+ .json with month and checksum). Never fails the build: without
// the file, locations show as unknown. DB-IP publishes a new file each month; this tries this month, then last month.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const edition = process.argv[2] ?? process.env.GEOIP_EDITION ?? 'country';
if (edition === 'off') {
  console.log('[geoip] GEOIP_EDITION=off: nothing to download');
  process.exit(0);
}
if (!['country', 'city'].includes(edition)) {
  console.error(`[geoip] unknown edition "${edition}" (country | city | off)`);
  process.exit(0);
}
const dir = path.join(root, 'backend', '.geoip');
const target = path.join(dir, `dbip-${edition}-lite.mmdb`);
const MAX_BYTES = 250 * 1024 * 1024;

const months = [0, 1].map((back) => {
  const d = new Date();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - back);
  return d.toISOString().slice(0, 7);
});

for (const month of months) {
  const url = `https://download.db-ip.com/free/dbip-${edition}-lite-${month}.mmdb.gz`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(180_000) });
    if (!res.ok) {
      console.warn(`[geoip] ${month}: HTTP ${res.status}`);
      continue;
    }
    const gz = Buffer.from(await res.arrayBuffer());
    const mmdb = gunzipSync(gz, { maxOutputLength: MAX_BYTES });
    // A MaxMind DB ends its data section with this marker; anything else isn't the file we asked for.
    if (mmdb.lastIndexOf(Buffer.from('\xab\xcd\xefMaxMind.com', 'latin1')) < 0) throw new Error('not a MaxMind DB file');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(`${target}.tmp`, mmdb);
    fs.renameSync(`${target}.tmp`, target);
    const meta = { edition, month, source: url, bytes: mmdb.length, sha256: createHash('sha256').update(mmdb).digest('hex'), fetchedAt: new Date().toISOString() };
    fs.writeFileSync(target.replace(/\.mmdb$/, '.json'), JSON.stringify(meta, null, 2));
    console.log(`[geoip] ${edition} ${month}: ${(mmdb.length / 1e6).toFixed(1)} MB → ${path.relative(root, target)}`);
    process.exit(0);
  } catch (err) {
    console.warn(`[geoip] ${month}: ${err?.message ?? err}`);
  }
}
console.warn('[geoip] no database downloaded; visitor locations will be unknown');
process.exit(0);
