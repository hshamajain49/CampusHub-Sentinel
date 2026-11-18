// Pure helpers for incoming page views: browser/OS/device from the user agent, path and referrer clean-up, IP
// truncation. Deliberately small and dependency-free (the popular parser's current major is AGPL-licensed).

export interface ParsedAgent {
  browser: string | null;
  browserVersion: string | null;
  os: string | null;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'bot' | 'unknown';
  isBot: boolean;
}

const BOT =
  /bot|crawl|spider|slurp|headless|lighthouse|pagespeed|gtmetrix|pingdom|uptime|monitor|curl\/|wget\/|python-|python\/|httpie|go-http|java\/|okhttp|axios|node-fetch|undici|postman|insomnia|scrapy|phantomjs|selenium|puppeteer|playwright|facebookexternalhit|preview|validator|feed|archiver/i;

const BROWSERS: [string, RegExp][] = [
  ['Edge', /Edg(?:e|A|iOS)?\/([\d.]+)/],
  ['Opera', /(?:OPR|OPiOS)\/([\d.]+)/],
  ['Samsung Internet', /SamsungBrowser\/([\d.]+)/],
  ['Firefox', /(?:Firefox|FxiOS)\/([\d.]+)/],
  ['Chrome', /(?:Chrome|CriOS)\/([\d.]+)/],
  ['Safari', /Version\/([\d.]+).*Safari\//],
];

export function parseUserAgent(ua: string | null | undefined): ParsedAgent {
  const s = (ua ?? '').slice(0, 512);
  if (!s) return { browser: null, browserVersion: null, os: null, deviceType: 'unknown', isBot: false };
  if (BOT.test(s)) return { browser: null, browserVersion: null, os: null, deviceType: 'bot', isBot: true };

  let browser: string | null = null;
  let browserVersion: string | null = null;
  for (const [name, re] of BROWSERS) {
    const m = re.exec(s);
    if (m) {
      browser = name;
      browserVersion = m[1]!.split('.')[0]!.slice(0, 20);
      break;
    }
  }

  const os = /Windows NT/.test(s)
    ? 'Windows'
    : /iPhone|iPod/.test(s)
      ? 'iOS'
      : /iPad/.test(s)
        ? 'iPadOS'
        : /Android/.test(s)
          ? 'Android'
          : /CrOS/.test(s)
            ? 'ChromeOS'
            : /Mac OS X|Macintosh/.test(s)
              ? 'macOS'
              : /Linux/.test(s)
                ? 'Linux'
                : null;

  const deviceType: ParsedAgent['deviceType'] = /iPad|Tablet|PlayBook|Silk|Kindle/.test(s) || (/Android/.test(s) && !/Mobile/.test(s))
    ? 'tablet'
    : /Mobi|iPhone|iPod|Android.*Mobile|Windows Phone/.test(s)
      ? 'mobile'
      : os
        ? 'desktop'
        : 'unknown';
  return { browser, browserVersion, os, deviceType, isBot: false };
}

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * The page's path for reporting: no query string or fragment (they can carry tokens, e.g. password-reset links),
 * record ids collapsed to :id (so /bookings/<uuid> pages group together and no id is stored), at most 300 chars.
 */
export function normalizePath(raw: string): string {
  let p = raw.split(/[?#]/)[0] ?? '/';
  try {
    p = decodeURIComponent(p);
  } catch {
    /* keep as is */
  }
  p = p
    .replace(UUID, ':id')
    .split('/')
    .map((seg) => (/^\d{2,}$/.test(seg) || /^[A-Za-z0-9_-]{24,}$/.test(seg) ? ':id' : seg))
    .join('/')
    .replace(/[^\w\-./:~@!$&'()*+,;=%]/g, '')
    .replace(/\/{2,}/g, '/');
  if (!p.startsWith('/')) p = `/${p}`;
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p.slice(0, 300);
}

const SEARCH = /(^|\.)(google|bing|duckduckgo|yahoo|baidu|yandex|ecosia|search\.brave|startpage|qwant)\./i;
const SOCIAL =
  /(^|\.)(facebook\.com|fb\.com|instagram\.com|t\.co|twitter\.com|x\.com|linkedin\.com|lnkd\.in|whatsapp\.com|wa\.me|youtube\.com|reddit\.com|t\.me|telegram\.org|snapchat\.com|pinterest\.)/i;

export type ReferrerSource = 'direct' | 'search' | 'social' | 'referral' | 'campaign' | 'internal';

/** Only the referring host is kept, never its full URL. */
export function classifyReferrer(referrer: string | null | undefined, appOrigins: string[], hasCampaign: boolean): { host: string | null; source: ReferrerSource } {
  let host: string | null = null;
  if (referrer) {
    try {
      const u = new URL(referrer);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        if (appOrigins.includes(u.origin)) return { host: null, source: 'internal' };
        host = u.hostname.toLowerCase().replace(/^www\./, '').slice(0, 253);
      }
    } catch {
      /* not a URL: treat as direct */
    }
  }
  if (hasCampaign) return { host, source: 'campaign' };
  if (!host) return { host: null, source: 'direct' };
  if (SEARCH.test(host)) return { host, source: 'search' };
  if (SOCIAL.test(host)) return { host, source: 'social' };
  return { host, source: 'referral' };
}

/** IPv4 → /24, IPv6 → /48 (the network, not the person). */
export function truncateIp(ip: string | null): string | null {
  if (!ip) return null;
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/i.exec(ip);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0`;
  if (ip.includes(':')) {
    const [head] = ip.split('::');
    const groups = (head ?? '').split(':').filter(Boolean);
    const full = ip.includes('::') ? [...groups, '0', '0', '0'].slice(0, 3) : ip.split(':').slice(0, 3);
    if (full.length === 3 && full.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return `${full.join(':')}::`;
  }
  return null;
}

/** CSS-breakpoint buckets (Tailwind's): enough to tell phones from laptops without a precise screen size. */
export function viewportBucket(width: number | undefined): 'xs' | 'sm' | 'md' | 'lg' | 'xl' | null {
  if (!width || width < 1) return null;
  if (width < 640) return 'xs';
  if (width < 768) return 'sm';
  if (width < 1024) return 'md';
  if (width < 1280) return 'lg';
  return 'xl';
}
