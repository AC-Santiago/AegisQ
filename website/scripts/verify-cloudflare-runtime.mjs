import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const website = fileURLToPath(new URL('../', import.meta.url));
const ports = { home: 4351, docs: 4352 };
const origins = { home: 'https://aegisq.dev', docs: 'https://docs.aegisq.dev' };
const localOrigins = Object.fromEntries(Object.entries(ports).map(([key, port]) => [key, `http://127.0.0.1:${port}`]));
const servers = [];
let browser;
let responses = 0;
const layouts = [];

function stopServers() {
  for (const server of servers) {
    if (!server.pid || server.exitCode !== null) continue;
    try {
      if (process.platform === 'win32') server.kill();
      else process.kill(-server.pid, 'SIGTERM');
    } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  }
}
process.once('exit', stopServers);
process.once('SIGINT', () => process.exit(130));
process.once('SIGTERM', () => process.exit(143));

function start(target) {
  const server = spawn(process.execPath, ['node_modules/wrangler/bin/wrangler.js', 'dev',
    '--config', `wrangler.${target}.json`, '--local', '--ip', '127.0.0.1',
    '--port', String(ports[target]), '--inspector-port', String(ports[target] + 5000),
    '--persist-to', `.wrangler/state-${target}`], {
    cwd: website, detached: process.platform !== 'win32',
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: 'true' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  servers.push(server);
  return new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error(`Emulator timeout: ${target}\n${output}`)), 60_000);
    const collect = (chunk) => {
      output += chunk;
      if (output.includes(`Ready on http://127.0.0.1:${ports[target]}`)) {
        clearTimeout(timeout);
        resolve();
      }
    };
    server.stdout.on('data', collect);
    server.stderr.on('data', collect);
    server.on('error', (error) => { clearTimeout(timeout); reject(error); });
    server.on('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`Emulator exited (${code}): ${target}\n${output}`));
    });
  });
}

async function request(target, pathname, status, destination) {
  const response = await fetch(`http://127.0.0.1:${ports[target]}${pathname}`, { redirect: 'manual' });
  assert.equal(response.status, status, `${target}${pathname}`);
  if (destination) {
    const actual = new URL(response.headers.get('location'), origins[target]);
    if (actual.hostname === '127.0.0.1') actual.host = new URL(origins[target]).host;
    actual.protocol = 'https:';
    assert.equal(actual.href, new URL(destination, origins[target]).href);
  }
  if (status === 404) {
    const text = await response.text();
    assert.match(text, /name="robots" content="noindex/);
    assert(text.includes(pathname.replace(/^\/next/, '').startsWith('/es/') ? 'Esta dirección' : 'There is no page'), `Wrong 404 locale: ${target}${pathname}`);
  }
  responses++;
}

try {
  await Promise.all(['home', 'docs'].map(start));
  for (const target of ['home', 'docs']) {
    await request(target, '/unknown-hosting-check/', 404);
    await request(target, '/es/unknown-hosting-check/', 404);
    await request(target, '/sitemap.xml', 200);
    await request(target, '/robots.txt', 200);
    await request(target, '/pagefind/pagefind.js', 200);
    const headers = await fetch(`http://127.0.0.1:${ports[target]}/404.html`);
    assert.equal(headers.headers.get('x-content-type-options'), 'nosniff');
  }
  await request('home', '/', 200);
  await request('home', '/es/', 200);
  await request('docs', '/', 302, '/getting-started/installation/');
  await request('docs', '/es/', 302, '/es/getting-started/installation/');
  await request('home', '/api-reference/aegiscipher/', 301, `${origins.docs}/api-reference/aegiscipher/`);
  await request('home', '/es/api-reference/aegiscipher/', 301, `${origins.docs}/es/api-reference/aegiscipher/`);
  await request('home', '/next/es/api-reference/aegiscipher/', 301, `${origins.docs}/next/es/api-reference/aegiscipher/`);
  for (const locale of ['', 'es/']) {
    await request('docs', `/next/${locale}`, 302, `/next/${locale}getting-started/installation/`);
    await request('docs', `/next/${locale}api-reference/aegiscipher/`, 200);
    await request('docs', `/next/${locale}unknown-hosting-check/`, 404);
  }
  await request('docs', '/next/pagefind/pagefind-entry.json', 200);

  // Browsers are optional locally; CI provisions a pinned browser explicitly.
  if (process.env.HOSTING_BROWSER === '1') {
    const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
    browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
    for (const width of [320, 375, 768, 1440]) {
      for (const language of ['en', 'es']) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
        const unexpected = [];
        const errors = [];
        // Intercept every HTTP request: production hosts are simulated, never fetched.
        await context.route(/^https?:\/\//, async (route) => {
          const url = new URL(route.request().url());
          const target = Object.keys(origins).find((key) => origins[key] === url.origin);
          if (Object.values(localOrigins).includes(url.origin)) return route.continue();
          if (!target) { unexpected.push(url.href); return route.abort(); }
          const response = await context.request.get(`http://127.0.0.1:${ports[target]}${url.pathname}${url.search}`, { maxRedirects: 0 });
          const headers = response.headers();
          if (headers.location) {
            const redirect = new URL(headers.location, url);
            const redirectTarget = Object.keys(origins).find((key) => origins[key] === redirect.origin) || target;
            if (Object.values(origins).includes(redirect.origin) || redirect.hostname === '127.0.0.1') {
              // Chromium cannot follow a cross-host 3xx supplied by route.fulfill.
              // HTTP redirect status/Location are checked separately above.
              redirect.host = new URL(localOrigins[redirectTarget]).host;
              redirect.protocol = 'http:';
            }
            headers.location = redirect.href;
          }
          await route.fulfill({ response, headers });
        });
        const page = await context.newPage();
        page.on('pageerror', (error) => errors.push(error.message));
        const prefix = language === 'es' ? '/es/' : '/';
        await page.goto(origins.home + prefix, { waitUntil: 'networkidle' });
        await page.evaluate(() => document.fonts.ready);
        assert(await page.locator('.aq-landing').isVisible());
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        assert.equal(await page.locator('link[rel=canonical]').getAttribute('href'), origins.home + prefix);
        await page.locator('site-search button[data-open-modal]').click();
        await page.locator('.pagefind-ui__search-input').fill('AegisCipher');
        const result = page.locator('.pagefind-ui__result-link[href*="/api-reference/aegiscipher/"]').first();
        await result.waitFor();
        const resultPath = new URL(await result.getAttribute('href'), page.url()).pathname;
        assert(resultPath.startsWith(language === 'es' ? '/es/' : '/api-reference/'));
        await result.click();
        await page.waitForURL((url) => [origins.docs, localOrigins.docs].includes(url.origin) && url.pathname.includes('/aegiscipher/'))
          .catch((error) => { throw new Error(`${error.message}\nURL: ${page.url()}\nRequests: ${unexpected.join(', ')}\nErrors: ${errors.join(', ')}`); });
        await page.waitForLoadState('networkidle');
        assert.equal(await page.locator('html').getAttribute('lang'), language);
        // Resume the simulated canonical docs origin before testing same-origin
        // storage and locale navigation; the emulator redirect changes origin.
        await page.goto(origins.docs + new URL(page.url()).pathname, { waitUntil: 'networkidle' });
        assert(await page.locator('.aq-chapters').isVisible());
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        if (width < 800) await page.locator('starlight-menu-button button').click();
        const theme = page.locator('starlight-theme-select select:visible').first();
        await theme.selectOption('dark');
        assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
        const locale = page.locator('starlight-lang-select select:visible').first();
        const alternate = origins.docs + (language === 'es' ? '/api-reference/aegiscipher/' : '/es/api-reference/aegiscipher/');
        await locale.selectOption(new URL(alternate).pathname);
        await page.waitForURL(alternate);
        assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
        // Version switches retain page, locale, hash and native theme state.
        await page.goto(`${alternate}#generate_keypair`, { waitUntil: 'networkidle' });
        await page.locator('.aq-doc-version select').selectOption(`/next${new URL(alternate).pathname}`);
        await page.waitForURL(`${origins.docs}/next${new URL(alternate).pathname}#generate_keypair`);
        await page.waitForLoadState('networkidle');
        assert.equal(await page.locator('[data-doc-channel]').getAttribute('data-doc-channel'), 'next');
        assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
        await page.locator('site-search button[data-open-modal]').click();
        await page.locator('.pagefind-ui__search-input').fill('AegisCipher');
        await page.locator('.pagefind-ui__result-link').first().waitFor();
        const nextPrefix = language === 'es' ? '/next/' : '/next/es/';
        const resultPaths = await page.locator('.pagefind-ui__result-link').evaluateAll((links) => links.map((link) => new URL(link.href).pathname));
        assert(resultPaths.length > 0 && resultPaths.every((pathname) => pathname.startsWith(nextPrefix) && pathname.startsWith('/next/es/') === (language === 'en')));
        await page.keyboard.press('Escape');
        if (width < 800) await page.locator('starlight-menu-button button').click();
        const nextPath = `/next${prefix}api-reference/aegiscipher/`;
        await page.locator('starlight-lang-select select:visible').first().selectOption(nextPath);
        await page.waitForURL(`${origins.docs}${nextPath}#generate_keypair`);
        await page.waitForLoadState('networkidle');
        assert.equal(await page.locator('html').getAttribute('lang'), language);
        await page.locator('.aq-doc-version select').selectOption(`${prefix}api-reference/aegiscipher/`);
        await page.waitForURL(`${origins.docs}${prefix}api-reference/aegiscipher/#generate_keypair`);
        await page.waitForLoadState('networkidle');
        assert.equal(await page.locator('[data-doc-channel]').getAttribute('data-doc-channel'), 'stable');
        await page.locator('a.aq-site-title').click();
        await page.waitForURL(origins.home + prefix);
        await page.waitForLoadState('networkidle');
        assert(await page.locator('.aq-landing').isVisible());
        assert.deepEqual(errors, []);
        assert.deepEqual(unexpected, []);
        layouts.push({ width, language, search: 'isolated stable/next', locale: 'switched in both channels', versions: 'round trip', homeRecovery: 'passed' });
        await context.unrouteAll({ behavior: 'wait' });
        await context.close();
      }
    }
  }
  const result = { responses, browser: browser ? 'Chromium' : 'not requested', cases: layouts };
  const output = path.resolve(process.env.UI_QA_DIR || path.join(website, '../.impeccable/review/hosting'));
  await mkdir(output, { recursive: true });
  await writeFile(path.join(output, `hosting-${browser ? 'browser' : 'http'}-report.json`), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
} finally {
  for (const context of browser?.contexts() || []) await context.unrouteAll({ behavior: 'ignoreErrors' });
  await browser?.close();
  stopServers();
}
