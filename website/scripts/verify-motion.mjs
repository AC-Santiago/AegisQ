import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const origin = process.env.DOCS_URL || 'http://127.0.0.1:4321';
const output = path.resolve(process.env.UI_QA_DIR || '.impeccable/review');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
const cases = [], failures = [], screenshots = [];
const check = (condition, message) => { if (!condition) failures.push(message); };
const settled = (page) => page.waitForFunction(() => document.getAnimations().every((animation) => animation.playState === 'finished'));
const snapshot = (page) => page.evaluate(() => ({
  events: window.motionEvents,
  overflow: document.documentElement.scrollWidth > innerWidth + 1,
  active: document.querySelectorAll('.aq-depth-enter, .aq-scroll-enter').length,
  pending: [...document.querySelectorAll('[data-aq-motion="pending"]')].map((element) => ({
    opacity: getComputedStyle(element).opacity, transform: getComputedStyle(element).transform,
  })),
}));

try {
  for (const theme of ['light', 'dark']) {
    for (const width of [375, 1440]) {
      for (const route of ['/', '/es/', '/api-reference/aegiscipher/', '/es/api-reference/aegiscipher/']) {
        const home = route === '/' || route === '/es/';
        const label = `${route} ${theme} ${width}px`;
        const context = await browser.newContext({ colorScheme: theme, reducedMotion: 'no-preference', viewport: { width, height: width === 375 ? 812 : 900 } });
        await context.addInitScript(() => {
          window.motionEvents = [];
          document.addEventListener('animationstart', (event) => {
            if (!['aq-depth-arrive', 'aq-reading-enter'].includes(event.animationName)) return;
            window.motionEvents.push({ name: event.animationName, target: event.target.className, testTarget: event.target.hasAttribute('data-motion-test'), scroll: scrollY, duration: getComputedStyle(event.target).animationDuration, delay: getComputedStyle(event.target).animationDelay });
          });
        });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.goto(`${origin}${route}`, { waitUntil: 'networkidle' });
        await settled(page);
        const before = await snapshot(page);
        check(!before.overflow && before.active === 0, `Unsettled opening or overflow: ${label}`);
        check(before.pending.length > 0 && before.pending.every((item) => item.opacity === '1' && item.transform === 'none'), `Offscreen content hidden while waiting: ${label}`);
        check(home ? before.events.some((event) => event.name === 'aq-depth-arrive' && event.duration === '0.64s') : !before.events.some((event) => event.name === 'aq-depth-arrive'), `Opening depth scope: ${label}`);
        if (home && width === 1440) check(before.events.filter((event) => event.name === 'aq-depth-arrive').map((event) => event.delay).join(',') === '0s,0.07s,0.14s', `Incorrect opening stagger: ${label}`);

        const target = await page.locator('[data-aq-motion="pending"]').first().elementHandle();
        await target.evaluate((element) => { element.setAttribute('data-motion-test', ''); element.scrollIntoView({ block: 'center', behavior: 'instant' }); });
        await page.waitForFunction(() => window.motionEvents.some((event) => event.name === 'aq-reading-enter' && event.scroll > 0));
        await settled(page);
        const after = await snapshot(page);
        check(after.active === 0 && !after.overflow, `Scroll animation retained transform or overflow: ${label}`);
        check(after.events.filter((event) => event.name === 'aq-reading-enter').every((event) => event.duration === '0.32s'), `Incorrect scroll duration: ${label}`);
        const capture = (theme === 'light' && width === 1440 && !route.startsWith('/es/')) || (theme === 'dark' && width === 375 && route.startsWith('/es/'));
        if (capture) {
          const filename = path.join(output, `motion-${home ? 'home' : 'docs'}-${theme}-${width}-scroll.png`);
          await page.screenshot({ path: filename, animations: 'disabled' });
          screenshots.push(filename);
        }
        await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
        await target.evaluate((element) => element.scrollIntoView({ block: 'center', behavior: 'instant' }));
        await settled(page);
        check((await snapshot(page)).events.filter((event) => event.testTarget).length === 1, `Entrances replay on reverse scroll: ${label}`);
        check(errors.length === 0, `Browser error: ${label}: ${errors.join(', ')}`);
        cases.push({ label, opening: before.events, scroll: after.events, fallbackVisible: true });
        await context.close();
      }
    }
  }

  for (const mode of ['reduced', 'no-javascript', 'no-observer']) {
    const context = await browser.newContext({ javaScriptEnabled: mode !== 'no-javascript', reducedMotion: mode === 'reduced' ? 'reduce' : 'no-preference' });
    if (mode === 'no-observer') await context.addInitScript(() => { delete window.IntersectionObserver; });
    const page = await context.newPage();
    for (const route of ['/', '/es/api-reference/aegiscipher/']) {
      await page.goto(`${origin}${route}`, { waitUntil: 'networkidle' });
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      await settled(page);
      check(await page.locator('.aq-depth-enter, .aq-scroll-enter').count() === 0, `Fallback still animates: ${mode} ${route}`);
      check(await page.evaluate(() => [...document.querySelectorAll('main h1, .sl-markdown-content p')].every((element) => getComputedStyle(element).opacity === '1')), `Fallback content not readable: ${mode} ${route}`);
      if (mode === 'reduced') check(await page.evaluate(() => document.getAnimations().length) === 0, `Reduced motion has active animations: ${route}`);
    }
    cases.push({ fallback: mode, passed: true });
    await context.close();
  }

  const context = await browser.newContext({ reducedMotion: 'no-preference' });
  const page = await context.newPage();
  await page.goto(`${origin}/es/api-reference/aegiscipher/`, { waitUntil: 'networkidle' });
  const anchor = await page.locator('.sl-markdown-content h2[id]').last().getAttribute('id');
  await page.goto(`${origin}/es/api-reference/aegiscipher/#${anchor}`, { waitUntil: 'networkidle' });
  check(await page.locator('.aq-depth-enter, .aq-scroll-enter').count() === 0, 'Deep link did not bypass entrance motion');
  await page.goto(`${origin}/es/api-reference/aegiscipher/`, { waitUntil: 'networkidle' });
  const focusedBlock = await page.locator('[data-aq-motion="pending"]:has(a, button)').last().elementHandle();
  check(Boolean(focusedBlock), 'Missing focus test target');
  if (focusedBlock) {
    await focusedBlock.evaluate((element) => element.querySelector('a, button').focus());
    check(await focusedBlock.getAttribute('data-aq-motion') === 'done' && await focusedBlock.evaluate((element) => !element.matches('.aq-scroll-enter')), 'Keyboard focus did not settle its block');
  }
  await page.goto(`${origin}/`);
  await page.waitForFunction(() => document.querySelector('.aq-depth-enter'));
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForFunction(() => document.getAnimations().length === 0 && !document.querySelector('.aq-depth-enter, .aq-scroll-enter'));
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto(`${origin}/es/api-reference/aegiscipher/`, { waitUntil: 'networkidle' });
  check(await page.locator('[data-aq-motion="pending"]').count() > 0, 'Missing same-document hash test targets');
  await page.evaluate((id) => { window.location.hash = id; }, anchor);
  await page.waitForFunction(() => !document.querySelector('[data-aq-motion="pending"], .aq-depth-enter, .aq-scroll-enter'));
  check(await page.evaluate(() => [...document.querySelectorAll('[data-aq-motion]')].every((element) => element.dataset.aqMotion === 'done')), 'Same-document hash did not settle reading blocks');
  await page.goto(`${origin}/404.html`, { waitUntil: 'networkidle' });
  check(await page.locator('.aq-not-found').count() === 1 && await page.locator('.aq-landing').count() === 0, '404 does not render the custom recovery surface');
  check(await page.locator('.aq-site-label').count() === 0, '404 claims to be documentation');
  await context.close();
  await writeFile(path.join(output, 'motion-report.json'), JSON.stringify({ cases, screenshots, failures, checks: 'Once-only entrances, no waiting invisibility, fallback/reduced/dynamic preference, deep links, focus, native404' }, null, 2));
  console.log(JSON.stringify({ cases: cases.length, screenshots: screenshots.length, failures }, null, 2));
  assert.equal(failures.length, 0, failures.join('\n'));
} finally {
  await browser.close();
}
