import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { lookupIp } from '../../src/lib/geoip.js';
import { classifyReferrer, normalizePath, parseUserAgent, truncateIp, viewportBucket } from '../../src/modules/analytics/parse.js';

const UA = {
  chromeWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70',
  safariIphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  chromeAndroid: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  androidTablet: 'Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  ipad: 'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
  firefoxMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:132.0) Gecko/20100101 Firefox/132.0',
  samsung: 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
  headless: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36',
  googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  curl: 'curl/8.5.0',
};

describe('parseUserAgent', () => {
  it.each([
    [UA.chromeWin, { browser: 'Chrome', browserVersion: '131', os: 'Windows', deviceType: 'desktop' }],
    [UA.edge, { browser: 'Edge', os: 'Windows', deviceType: 'desktop' }],
    [UA.safariIphone, { browser: 'Safari', browserVersion: '18', os: 'iOS', deviceType: 'mobile' }],
    [UA.chromeAndroid, { browser: 'Chrome', os: 'Android', deviceType: 'mobile' }],
    [UA.androidTablet, { browser: 'Chrome', os: 'Android', deviceType: 'tablet' }],
    [UA.ipad, { browser: 'Safari', os: 'iPadOS', deviceType: 'tablet' }],
    [UA.firefoxMac, { browser: 'Firefox', browserVersion: '132', os: 'macOS', deviceType: 'desktop' }],
    [UA.samsung, { browser: 'Samsung Internet', os: 'Android', deviceType: 'mobile' }],
  ])('%s', (ua, expected) => {
    expect(parseUserAgent(ua)).toMatchObject({ ...expected, isBot: false });
  });
  it.each([UA.headless, UA.googlebot, UA.curl, 'python-requests/2.32', 'Playwright/1.56'])('flags %s as a bot', (ua) => {
    expect(parseUserAgent(ua)).toMatchObject({ isBot: true, deviceType: 'bot' });
  });
  it('handles a missing user agent', () => expect(parseUserAgent(null).deviceType).toBe('unknown'));
});

describe('normalizePath', () => {
  it.each([
    ['/reset-password?token=abc123secret', '/reset-password'],
    ['/bookings/3f2b6c1e-9a4d-4e8f-b1c2-0d9e8f7a6b5c/edit', '/bookings/:id/edit'],
    ['/admin/users/12345', '/admin/users/:id'],
    ['/venues#gallery', '/venues'],
    ['venues/', '/venues'],
    ['//a///b/', '/a/b'],
    ['/', '/'],
    ['/x/aGVsbG8td29ybGQtdGhpcy1pcy1hLXRva2Vu', '/x/:id'],
    ['/<script>alert(1)</script>', '/scriptalert(1)/script'],
  ])('%s → %s', (input, expected) => expect(normalizePath(input)).toBe(expected));
  it('caps the length', () => expect(normalizePath(`/${'a'.repeat(1000)}`).length).toBeLessThanOrEqual(300));
});

describe('classifyReferrer', () => {
  const app = ['https://campushub.pages.dev'];
  it.each([
    [undefined, false, { host: null, source: 'direct' }],
    ['https://www.google.com/search?q=campus', false, { host: 'google.com', source: 'search' }],
    ['https://l.instagram.com/?u=x', false, { host: 'l.instagram.com', source: 'social' }],
    ['https://t.co/abc', false, { host: 't.co', source: 'social' }],
    ['https://college.edu/notices', false, { host: 'college.edu', source: 'referral' }],
    ['https://campushub.pages.dev/venues', false, { host: null, source: 'internal' }],
    ['https://college.edu/notices', true, { host: 'college.edu', source: 'campaign' }],
    ['javascript:alert(1)', false, { host: null, source: 'direct' }],
  ])('%s (campaign: %s)', (ref, campaign, expected) => expect(classifyReferrer(ref, app, campaign)).toEqual(expected));
});

describe('IP and viewport', () => {
  it.each([
    ['203.0.113.77', '203.0.113.0'],
    ['::ffff:198.51.100.9', '198.51.100.0'],
    ['2001:db8:85a3:8d3:1319:8a2e:370:7348', '2001:db8:85a3::'],
    ['2001:db8::1', '2001:db8:0::'],
    ['not-an-ip', null],
  ])('truncates %s → %s', (ip, expected) => expect(truncateIp(ip)).toBe(expected));
  it.each([
    [390, 'xs'],
    [700, 'sm'],
    [800, 'md'],
    [1100, 'lg'],
    [1920, 'xl'],
    [0, null],
  ])('viewport %i → %s', (w, b) => expect(viewportBucket(w)).toBe(b));
});

const dbFile = path.resolve(process.cwd(), '.geoip', 'dbip-country-lite.mmdb');
describe.skipIf(!fs.existsSync(dbFile))('GeoIP (DB-IP Lite country, downloaded by npm run geoip:fetch)', () => {
  it('finds countries for public addresses and nothing for private ones', () => {
    expect(lookupIp('8.8.8.8')?.country).toBe('US');
    expect(lookupIp('1.1.1.1')?.country).toMatch(/^[A-Z]{2}$/);
    expect(lookupIp('10.1.2.3')).toBeNull();
    expect(lookupIp('127.0.0.1')).toBeNull();
    expect(lookupIp('nonsense')).toBeNull();
  });
});
