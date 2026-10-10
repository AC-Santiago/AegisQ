import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const origin = process.env.DOCS_URL || 'http://127.0.0.1:4321';
const output = path.resolve(process.env.UI_QA_DIR || '.impeccable/review');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
const matrix = [], screenshots = [], failures = [];
const check = (condition, message) => { if (!condition) failures.push(message); };

try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext({ colorScheme: theme, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = [], externalRequests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => {
      if (request.url().startsWith('http') && !request.url().startsWith(origin)) externalRequests.push(request.url());
    });
    for (const route of ['/', '/es/', '/api-reference/aegiscipher/', '/es/api-reference/aegiscipher/']) {
      const home = route === '/' || route === '/es/';
      const spanish = route.startsWith('/es/');
      for (const width of home ? [320, 375, 768, 1024, 1440] : [375, 1440]) {
        await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
        await page.goto(`${origin}${route}`, { waitUntil: 'networkidle' });
        await page.evaluate(() => document.fonts.ready);
        const metrics = await page.evaluate(() => {
          const heading = document.querySelector('h1');
          return {
            scrollWidth: document.documentElement.scrollWidth,
            titleTop: heading.getBoundingClientRect().top,
            headerBottom: document.querySelector('.page > header').getBoundingClientRect().bottom,
            headings: document.querySelectorAll('h1').length,
            theme: document.documentElement.dataset.theme,
            sidebar: document.documentElement.hasAttribute('data-has-sidebar'),
            font: document.fonts.check('600 24px "Schibsted Grotesk"'),
            animationCount: document.getAnimations().length,
            columns: document.querySelector('.aq-desk') ? getComputedStyle(document.querySelector('.aq-desk')).gridTemplateColumns : null,
            chapterLinks: document.querySelectorAll('.aq-chapters a').length,
            entryLinks: [...document.querySelectorAll('.aq-entry-paths a')].map((a) => a.pathname),
            packet: [...document.querySelectorAll('.aq-packet-parts strong')].map((part) => part.textContent),
          };
        });
        const label = `${route} ${width}px ${theme}`;
        matrix.push({ route, width, theme, ...metrics });
        check(metrics.scrollWidth <= width + 1, `Horizontal overflow: ${label}`);
        check(metrics.titleTop >= metrics.headerBottom - 1, `Heading hidden by header: ${label}`);
        check(metrics.headings === 1, `Duplicate/missing H1: ${label}`);
        check(metrics.theme === theme && metrics.font, `Theme/font mismatch: ${label}`);
        check(metrics.animationCount === 0, `Reduced motion not honored: ${label}`);
        if (home) {
          check(await page.locator('.aq-site-label').count() === 0, `Home brand includes docs label: ${label}`);
          check(await page.locator('.aq-masthead starlight-theme-select select').isVisible() && await page.locator('.aq-masthead starlight-lang-select select').isVisible(), `Hidden home selectors: ${label}`);
          check(!metrics.sidebar && metrics.chapterLinks === 0, `Docs frame leaked onto home: ${label}`);
          check(metrics.entryLinks.length === 5 && metrics.entryLinks.every((link) => spanish ? link.startsWith('/es/') : !link.startsWith('/es/')), `Entry link locale: ${label}`);
          check(metrics.packet.join('|') === (spanish ? 'Capsule ML-KEM|Nonce AES|Tag de autenticación|Ciphertext' : 'ML-KEM capsule|AES nonce|Auth tag|Ciphertext'), `Packet order: ${label}`);
          check(metrics.columns.split(' ').length === (width >= 1184 ? 3 : width >= 800 ? 2 : 1), `Wrong column count: ${label}`);
          check(await page.locator('.aq-example pre').first().innerText().then((text) => text.includes('assert plaintext == b"Hello, AegisQ"')), `Incomplete roundtrip: ${label}`);
        } else {
          check(await page.locator('.aq-site-label').count() === 1, `Docs brand lost its label: ${label}`);
          check(metrics.sidebar && metrics.chapterLinks === 4, `Docs navigation regression: ${label}`);
        }
        if (width === 375 || width === 1440) {
          const name = `landing-${home ? 'home' : 'api'}-${spanish ? 'es' : 'en'}-${theme}-${width === 375 ? 'mobile' : 'desktop'}`;
          const screenshot = path.join(output, `${name}.png`);
          await page.screenshot({ path: screenshot, fullPage: true, animations: 'disabled' });
          screenshots.push(screenshot);
          if (home && width === 1440) await page.screenshot({ path: path.join(output, `${name}-viewport.png`), animations: 'disabled' });
        }
      }
    }
    check(errors.length === 0, `Browser errors: ${errors.join(', ')}`);
    check(externalRequests.length === 0, `External runtime requests: ${externalRequests.join(', ')}`);
    await context.close();
  }
  const context = await browser.newContext({ viewport: { width: 375, height: 812 }, reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto(`${origin}/es/`, { waitUntil: 'networkidle' });
  await page.locator('.aq-masthead starlight-theme-select select').selectOption('light');
  check(await page.locator('html').getAttribute('data-theme') === 'light', 'Mobile home theme control failed');
  await page.locator('.aq-masthead starlight-lang-select select').selectOption('/');
  await page.waitForURL((url) => url.pathname === '/');
  check(await page.locator('.aq-open-docs').getAttribute('href') === '/getting-started/installation/', 'Mobile home language switch failed');
  await page.goto(`${origin}/es/`, { waitUntil: 'networkidle' });
  await page.keyboard.press('Tab');
  check(await page.evaluate(() => document.activeElement.textContent.includes('contenido')), 'Home skip link is not first');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Tab');
  check(await page.evaluate(() => document.querySelector('main').contains(document.activeElement)), 'Home skip link did not bypass navigation');
  await page.locator('.aq-open-docs').click();
  await page.waitForURL(`${origin}/es/getting-started/installation/`);
  check(await page.locator('.aq-chapters a').count() === 4, 'Home-to-docs transition lost chapter navigation');
  await context.close();

  const animated = await browser.newContext({ reducedMotion: 'no-preference', viewport: { width: 1440, height: 900 } });
  const motionPage = await animated.newPage();
  await motionPage.goto(`${origin}/`);
  await motionPage.waitForFunction(() => document.querySelector('.aq-introduction')?.getAttribute('data-aq-motion') === 'done');
  await animated.close();
  await writeFile(path.join(output, 'landing-report.json'), JSON.stringify({ matrix, screenshots, failures, browser: 'Chromium', interactions: 'Home keyboard skip, docs entry, soft/reduced motion' }, null, 2));
  console.log(JSON.stringify({ layouts: matrix.length, screenshots: screenshots.length, failures }, null, 2));
  assert.equal(failures.length, 0, failures.join('\n'));
} finally {
  await browser.close();
}
