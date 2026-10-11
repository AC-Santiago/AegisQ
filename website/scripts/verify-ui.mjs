import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const output = path.resolve(process.env.UI_QA_DIR || '.impeccable/review');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH,
  headless: true,
});
const origin = process.env.DOCS_URL || 'http://127.0.0.1:4321';
const routes = ['/', '/es/', '/api-reference/aegiscipher/', '/es/api-reference/aegiscipher/'];
const widths = [375, 768, 799, 800, 1024, 1440];
const interactionsOnly = process.env.UI_INTERACTIONS_ONLY === '1';
const previous = interactionsOnly ? JSON.parse(await readFile(path.join(output, 'qa-report.json'), 'utf8')) : null;
const matrix = previous?.matrix || [];
const failures = [];
const screenshots = previous?.screenshots || [];
const check = (condition, message) => { if (!condition) failures.push(message); };

async function verifyMenuCentering(page, label) {
  if (['/', '/es/'].includes(new URL(page.url()).pathname)) {
    check(await page.locator('starlight-menu-button button').count() === 0, `Unexpected splash menu: ${label}`);
    return null;
  }
  const metrics = await page.locator('starlight-menu-button button').evaluate((button) => {
    const rect = button.getBoundingClientRect();
    const icon = [...button.querySelectorAll('svg')].find((svg) => svg.getBoundingClientRect().width > 0);
    const masthead = document.querySelector('.aq-masthead').getBoundingClientRect();
    const center = (box) => ({ x: box.x + box.width / 2, y: box.y + box.height / 2 });
    const visible = rect.width > 0 && rect.height > 0;
    const iconCenter = icon && center(icon.getBoundingClientRect());
    const buttonCenter = center(rect);
    return {
      visible,
      width: rect.width,
      height: rect.height,
      iconOffsetX: iconCenter ? iconCenter.x - buttonCenter.x : null,
      iconOffsetY: iconCenter ? iconCenter.y - buttonCenter.y : null,
      mastheadOffsetY: buttonCenter.y - center(masthead).y,
    };
  });
  const mobile = page.viewportSize().width < 800;
  check(metrics.visible === mobile, `Wrong menu visibility: ${label}`);
  if (mobile) {
    check(metrics.width >= 44 && metrics.height >= 44, `Small menu target: ${label}`);
    check(metrics.iconOffsetX !== null && Math.abs(metrics.iconOffsetX) <= 1, `Menu icon off-center horizontally: ${label} (${metrics.iconOffsetX}px)`);
    check(metrics.iconOffsetY !== null && Math.abs(metrics.iconOffsetY) <= 1, `Menu icon off-center vertically: ${label} (${metrics.iconOffsetY}px)`);
    check(Math.abs(metrics.mastheadOffsetY) <= 1, `Menu button off-center in masthead: ${label}`);
  }
  return metrics;
}

try {
  for (const theme of interactionsOnly ? [] : ['light', 'dark']) {
    const context = await browser.newContext({ colorScheme: theme, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const externalRequests = [];
    page.on('request', (request) => {
      if (!request.url().startsWith(origin) && request.url().startsWith('http')) externalRequests.push(request.url());
    });
    for (const width of widths) {
      await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
      for (const route of routes) {
        await page.goto(`${origin}${route}`, { waitUntil: 'networkidle' });
        await page.evaluate(() => document.fonts.ready);
        const metrics = await page.evaluate(() => {
          const title = document.querySelector('h1');
          const header = document.querySelector('.page > header');
          const chapters = [...document.querySelectorAll('.aq-chapters a')];
          return {
            viewport: innerWidth,
            scrollWidth: document.documentElement.scrollWidth,
            title: title.textContent,
            titleTop: title.getBoundingClientRect().top,
            headerBottom: header.getBoundingClientRect().bottom,
            theme: document.documentElement.dataset.theme,
            font: document.fonts.check('400 16px "Schibsted Grotesk"'),
            chapterLinks: chapters.map((a) => a.getAttribute('href')),
            currentChapters: chapters.filter((a) => a.hasAttribute('aria-current')).length,
            animations: document.getAnimations().length,
          };
        });
        const label = `${route} ${width}px ${theme}`;
        metrics.menu = await verifyMenuCentering(page, label);
        if (metrics.menu?.visible) {
          await page.locator('starlight-menu-button button').click();
          metrics.expandedMenu = await verifyMenuCentering(page, `Expanded ${label}`);
          await page.keyboard.press('Escape');
          await verifyMenuCentering(page, `Collapsed after Escape ${label}`);
        }
        matrix.push({ route, width, theme, ...metrics });
        check(metrics.scrollWidth <= width + 1, `Horizontal overflow: ${label} (${metrics.scrollWidth}px)`);
        check(metrics.titleTop >= metrics.headerBottom - 1, `Title obscured: ${label}`);
        check(metrics.theme === theme, `Wrong theme: ${label}`);
        check(metrics.font, `Local font not ready: ${label}`);
        check(metrics.animations === 0, `Reduced-motion animation: ${label}`);
        check(metrics.currentChapters === (route.includes('api-reference') ? 1 : 0), `Wrong chapter state: ${label}`);
        check(metrics.chapterLinks.every((href) => href.startsWith(route.startsWith('/es/') ? '/es/' : '/') && (route.startsWith('/es/') || !href.startsWith('/es/'))), `Wrong chapter locale: ${label}`);

        if (width === 375 || width === 1440) {
          const language = route.startsWith('/es/') ? 'es' : 'en';
          const surface = route.includes('api-reference') ? 'api' : 'home';
          const device = width === 375 ? 'mobile' : 'desktop';
          const stem = `${device}-${surface}-${language}-${theme}`;
          const screenshot = path.join(output, `${stem}.png`);
          await page.screenshot({ path: screenshot, fullPage: true, animations: 'disabled' });
          screenshots.push(screenshot);
          if (surface === 'api') {
            await page.screenshot({ path: path.join(output, `${stem}-viewport.png`), animations: 'disabled' });
          }
        }
      }
    }
    check(errors.length === 0, `Browser errors (${theme}): ${errors.join(', ')}`);
    check(externalRequests.length === 0, `External runtime requests (${theme}): ${externalRequests.join(', ')}`);
    await context.close();
  }

  const context = await browser.newContext({ viewport: { width: 375, height: 812 }, colorScheme: 'light' });
  await writeFile(path.join(output, 'qa-report.json'), JSON.stringify({ matrix, screenshots, failures, interactions: 'Pending', browser: 'Chromium' }, null, 2));
  const page = await context.newPage();
  await page.goto(`${origin}/es/api-reference/aegiscipher/`, { waitUntil: 'networkidle' });
  await page.keyboard.press('Tab');
  check(await page.evaluate(() => document.activeElement.textContent.includes('contenido')), 'Skip link is not first keyboard stop');
  await page.keyboard.press('Enter');
  check(await page.evaluate(() => location.hash === '#_top'), 'Skip link did not reach the content anchor');
  await page.keyboard.press('Tab');
  check(await page.evaluate(() => document.querySelector('main').contains(document.activeElement)), 'Skip link did not bypass navigation in the tab sequence');

  const menu = page.locator('starlight-menu-button button');
  await menu.focus();
  await page.keyboard.press('Enter');
  check(await page.locator('starlight-menu-button').getAttribute('aria-expanded') === 'true', 'Mobile menu did not open with keyboard');
  check(await menu.getAttribute('aria-expanded') === 'true', 'Menu button exposes stale collapsed state');
  check(await page.locator('#starlight__sidebar').isVisible(), 'Mobile sidebar invisible');
  await verifyMenuCentering(page, 'Expanded menu 375px');
  await page.keyboard.press('Escape');
  check(await page.locator('starlight-menu-button').getAttribute('aria-expanded') === 'false', 'Mobile menu did not close with Escape');
  check(await menu.getAttribute('aria-expanded') === 'false', 'Menu button exposes stale expanded state');
  check(await menu.evaluate((element) => document.activeElement === element), 'Menu focus not restored');
  await verifyMenuCentering(page, 'Collapsed menu after Escape 375px');

  await page.keyboard.press('Control+k');
  await page.locator('dialog[open]').waitFor();
  const searchInput = page.locator('.pagefind-ui__search-input');
  await searchInput.fill('AegisCipher');
  await page.locator('.pagefind-ui__result-link').first().waitFor();
  const results = await page.locator('.pagefind-ui__result-link').evaluateAll((links) => links.map((a) => a.pathname));
  check(results.length > 0 && results.every((href) => href.startsWith('/es/')), 'Spanish search returned wrong locale');
  await searchInput.fill('no-such-aegisq-page-927410');
  await page.waitForFunction(() => document.querySelector('.pagefind-ui__message')?.textContent.includes('0'));
  await page.keyboard.press('Escape');
  check(await page.locator('dialog[open]').count() === 0, 'Search did not close with Escape');

  await menu.click();
  const languageSelect = page.locator('.sidebar starlight-lang-select select');
  const englishPath = await languageSelect.locator('option').evaluateAll((options) => options.find((option) => !option.value.startsWith('/es/')).value);
  await languageSelect.selectOption(englishPath);
  await page.waitForURL((url) => url.pathname === '/api-reference/aegiscipher/');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('.aq-masthead starlight-theme-select select').selectOption('dark');
  check(await page.locator('html').getAttribute('data-theme') === 'dark', 'Native theme selector did not change theme');

  for (const width of [320, 720]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`${origin}/es/api-reference/aegiscipher/`, { waitUntil: 'networkidle' });
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `Stress-width overflow: ${width}px`);
    await verifyMenuCentering(page, `Stress-width menu ${width}px`);
  }
  await context.close();

  await writeFile(path.join(output, 'qa-report.json'), JSON.stringify({ matrix, screenshots, failures, interactions: 'Keyboard skip/menu/Escape, Pagefind populated/empty, locale and theme selectors, 320/720px stress', browser: 'Chromium' }, null, 2));
  console.log(JSON.stringify({ layouts: matrix.length, screenshots: screenshots.length, failures }, null, 2));
  assert.equal(failures.length, 0, failures.join('\n'));
} finally {
  await browser.close();
}
