import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const origin = process.env.DOCS_URL || 'http://127.0.0.1:4321';
const output = path.resolve(process.env.UI_QA_DIR || '.impeccable/review');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
const matrix = [], failures = [], screenshots = [];
const check = (condition, message) => { if (!condition) failures.push(message); };

try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext({ colorScheme: theme, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    for (const route of ['/404.html', '/es/404/']) {
      const spanish = route.startsWith('/es/');
      for (const width of [320, 375, 768, 1440]) {
        await page.setViewportSize({ width, height: width < 768 ? 812 : 900 });
        await page.goto(`${origin}${route}`, { waitUntil: 'networkidle' });
        await page.evaluate(() => document.fonts.ready);
        const metrics = await page.evaluate(() => ({
          heading: document.querySelector('h1').textContent,
          headings: document.querySelectorAll('h1').length,
          overflow: document.documentElement.scrollWidth > innerWidth + 1,
          theme: document.documentElement.dataset.theme,
          titleTop: document.querySelector('h1').getBoundingClientRect().top,
          headerBottom: document.querySelector('.page > header').getBoundingClientRect().bottom,
          sidebar: document.documentElement.hasAttribute('data-has-sidebar'),
          home: document.querySelector('.aq-not-found .aq-open-docs').getAttribute('href'),
          links: [...document.querySelectorAll('.aq-not-found a')].map((link) => link.pathname),
          localeOptions: [...document.querySelectorAll('.aq-masthead starlight-lang-select option')].map((option) => option.value),
          robots: [...document.querySelectorAll('meta[name="robots"]')].map((meta) => meta.content),
        }));
        const label = `${route} ${theme} ${width}px`;
        matrix.push({ route, theme, width, ...metrics });
        check(metrics.headings === 1 && metrics.heading === (spanish ? 'Página no encontrada' : 'Page not found'), `Incorrect error heading: ${label}`);
        check(!metrics.overflow && metrics.titleTop >= metrics.headerBottom, `Error layout regression: ${label}`);
        check(metrics.theme === theme && !metrics.sidebar, `Incorrect error frame: ${label}`);
        check(metrics.home.replace(/\/$/, '') === (spanish ? '/es' : ''), `Incorrect home recovery: ${label}`);
        check(metrics.links.every((link) => spanish ? link === '/es' || link.startsWith('/es/') : !link.startsWith('/es/')), `Recovery locale mismatch: ${label}`);
        check(metrics.robots.some((value) => value.includes('noindex')), `404 is indexable: ${label}`);
        check(metrics.localeOptions.includes('/404.html') && metrics.localeOptions.includes('/es/404/'), `Error locale switch targets missing routes: ${label}`);
        check(await page.locator('.aq-landing, .aq-site-label, .aq-chapters').count() === 0, `Home/docs leaked onto error: ${label}`);
        check(await page.locator('.aq-masthead starlight-lang-select select').isVisible() && await page.locator('.aq-masthead starlight-theme-select select').isVisible(), `Hidden error controls: ${label}`);
        if ([375, 1440].includes(width)) {
          const filename = path.join(output, `404-${spanish ? 'es' : 'en'}-${theme}-${width}.png`);
          await page.screenshot({ path: filename, fullPage: true, animations: 'disabled' });
          screenshots.push(filename);
        }
      }
    }
    check(errors.length === 0, `404 browser errors: ${errors.join(', ')}`);
    await context.close();
  }
  const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const page = await context.newPage();
  await page.goto(`${origin}/404.html`, { waitUntil: 'networkidle' });
  await page.locator('.aq-masthead starlight-lang-select select').selectOption('/es/404/');
  await page.waitForURL(`${origin}/es/404/`);
  check(await page.locator('h1').innerText() === 'Página no encontrada', '404 language switch did not localize the error');
  await page.locator('.aq-masthead starlight-theme-select select').selectOption('dark');
  check(await page.locator('html').getAttribute('data-theme') === 'dark', '404 theme switch failed');
  await page.keyboard.press('Tab');
  await page.locator('.aq-not-found .aq-open-docs').click();
  await page.waitForURL((url) => url.pathname.replace(/\/$/, '') === '/es');
  check(await page.locator('.aq-landing').count() === 1, '404 home recovery failed');
  const missing = await page.goto(`${origin}/missing-aegisq-page-for-qa/`, { waitUntil: 'networkidle' });
  check(missing.status() === 404 && await page.locator('.aq-not-found').count() === 1, 'Preview does not serve custom404 for an unknown route');
  await context.close();
  await writeFile(path.join(output, '404-report.json'), JSON.stringify({ matrix, screenshots, failures, checks: 'Locales, controls, recovery links, unknown URL status404, noindex, responsive error frame' }, null, 2));
  console.log(JSON.stringify({ layouts: matrix.length, screenshots: screenshots.length, failures }, null, 2));
  assert.equal(failures.length, 0, failures.join('\n'));
} finally {
  await browser.close();
}
