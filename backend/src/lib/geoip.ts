// Offline IP → country (and city, with the city edition) using DB-IP Lite (CC BY 4.0, https://db-ip.com).
// No IP address leaves the server. A missing or unreadable database only means "location unknown".
import fs from 'node:fs';
import path from 'node:path';
import { Reader, type CityResponse } from 'maxmind';
import { config } from '../config/env.js';
import { logger } from './logger.js';

export interface GeoLocation {
  country: string | null; // ISO 3166-1 alpha-2
  region: string | null;
  city: string | null;
}

let reader: Reader<CityResponse> | null | undefined;
let meta: { edition: string; month: string } | null = null;

function load(): Reader<CityResponse> | null {
  if (reader !== undefined) return reader;
  reader = null;
  if (config.GEOIP_EDITION === 'off') return reader;
  const name = `dbip-${config.GEOIP_EDITION}-lite.mmdb`;
  const file = [path.resolve(process.cwd(), config.GEOIP_DIR, name), path.resolve(process.cwd(), 'backend', config.GEOIP_DIR, name)].find((f) =>
    fs.existsSync(f),
  );
  if (!file) {
    logger.warn({ edition: config.GEOIP_EDITION }, 'GeoIP database not found (run npm run geoip:fetch); locations will be unknown');
    return reader;
  }
  try {
    reader = new Reader<CityResponse>(fs.readFileSync(file));
    try {
      meta = JSON.parse(fs.readFileSync(file.replace(/\.mmdb$/, '.json'), 'utf8'));
    } catch {
      meta = { edition: config.GEOIP_EDITION, month: 'unknown' };
    }
    logger.info({ edition: config.GEOIP_EDITION, month: meta?.month }, 'GeoIP database loaded');
  } catch (err) {
    logger.error({ err }, 'GeoIP database unreadable; locations will be unknown');
  }
  return reader;
}

export function geoipInfo(): { edition: string; month: string } | null {
  load();
  return meta;
}

const clean = (s: string | undefined, max: number) => (s ? s.slice(0, max) : null);

export function lookupIp(ip: string | null): GeoLocation | null {
  if (!ip) return null;
  const r = load();
  if (!r) return null;
  try {
    const hit = r.get(ip);
    if (!hit) return null;
    const country = hit.country?.iso_code ?? hit.registered_country?.iso_code;
    return {
      country: country && /^[A-Z]{2}$/.test(country) ? country : null,
      region: clean(hit.subdivisions?.[0]?.names?.en, 80),
      city: clean(hit.city?.names?.en, 80),
    };
  } catch {
    return null; // not an IP the database understands
  }
}
