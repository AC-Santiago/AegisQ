import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const website = fileURLToPath(new URL('../', import.meta.url));
const origins = { home: 'https://aegisq.dev', docs: 'https://docs.aegisq.dev' };
const bundles = {};
const html = new Map();

async function walk(directory, prefix = '') {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.posix.join(prefix, entry.name);
    assert(!entry.isSymbolicLink(), `Symlink not allowed: ${file}`);
    if (entry.isDirectory()) result.push(...await walk(path.join(directory, entry.name), file));
    else result.push(file);
  }
  return result;
}

for (const [target, origin] of Object.entries(origins)) {
  const config = JSON.parse(await readFile(path.join(website, `wrangler.${target}.json`), 'utf8'));
  assert.deepEqual(Object.keys(config).sort(), ['$schema', 'assets', 'compatibility_date', 'name', 'preview_urls', 'routes', 'workers_dev'].sort());
  assert.deepEqual(config.routes, [{ pattern: new URL(origin).hostname, custom_domain: true }]);
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.assets, { directory: `./dist/cloudflare/${target}`, html_handling: 'auto-trailing-slash', not_found_handling: '404-page' });
  const directory = path.join(website, config.assets.directory);
  const files = await walk(directory);
  assert(files.length <= 20_000, 'Workers Free file-count limit exceeded');
  let largest = 0;
  for (const file of files) {
    const size = (await stat(path.join(directory, file))).size;
    assert(size <= 25 * 1024 * 1024, `Asset too large: ${file}`);
    largest = Math.max(largest, size);
    if (file.endsWith('.html')) {
      const text = await readFile(path.join(directory, file), 'utf8');
      assert(!text.includes('aegisq-pqc.readthedocs.io'), `Old host in ${file}`);
      assert(!/<option[^>]*value="https?:/.test(text), `Locale options must remain pathnames: ${file}`);
      assert(text.includes(`class="aq-site-title" href="${origins.home}/${file.replace(/^next\//, '').startsWith('es/') ? 'es/' : ''}"`), `Brand link must recover the localized home: ${file}`);
      html.set(`${target}/${file}`, text);
      const error = /(?:^|\/)404(?:\/index)?\.html$/.test(file);
      if (error) assert.match(text, /name="robots" content="noindex/);
      else assert(text.includes(`rel="canonical" href="${origin}/`), `Wrong canonical in ${file}`);
      if (file.startsWith('next/')) assert.match(text, /name="robots" content="noindex/);
    }
  }
  assert(files.includes('404.html') && files.includes('es/404.html'));
  assert(files.includes('pagefind/pagefind.js'), 'Search index missing');
  const sitemap = await readFile(path.join(directory, 'sitemap.xml'), 'utf8');
  const locations = [...sitemap.matchAll(/<loc>(.*?)<\/loc>/g)].map((match) => match[1]);
  const indexable = files.filter((file) => file.endsWith('.html') && !file.startsWith('next/') && !/(?:^|\/)404(?:\/index)?\.html$/.test(file));
  assert.equal(locations.length, indexable.length);
  if (target === 'home') assert.equal(locations.length, 2);
  assert(locations.every((url) => url.startsWith(`${origin}/`) && !url.includes('/404')));
  for (const base of target === 'docs' ? ['', 'next/'] : ['']) {
    const search = JSON.parse(await readFile(path.join(directory, base, 'pagefind/pagefind-entry.json'), 'utf8'));
    assert.deepEqual(Object.keys(search.languages).sort(), ['en', 'es']);
    for (const language of ['en', 'es']) {
      const docsDirectory = path.join(website, 'dist/cloudflare/docs');
      const docsFiles = await walk(docsDirectory);
      const expected = docsFiles.filter((file) => file.startsWith('next/') === Boolean(base) && file.endsWith('/index.html') && !file.includes('/404/') && file.slice(base.length).startsWith('es/') === (language === 'es'));
      assert.equal(search.languages[language].page_count, expected.length, `${base}${language} search index excludes homes/errors`);
    }
  }
  assert.equal(files.includes('index.html'), target === 'home');
  assert.equal(files.includes('es/index.html'), target === 'home');
  bundles[target] = { files: new Set(files), directory };
  console.log(`${target}: ${files.length} assets, largest ${largest} bytes; Free limits OK`);
}

function resolve(url) {
  const target = Object.keys(origins).find((key) => origins[key] === url.origin);
  if (!target) return;
  if (target === 'docs' && ['/', '/es', '/es/'].includes(url.pathname)) {
    url.pathname = `${url.pathname.startsWith('/es') ? '/es' : ''}/getting-started/installation/`;
  }
  if (target === 'docs' && ['/next', '/next/', '/next/es', '/next/es/'].includes(url.pathname)) {
    url.pathname = `/next${url.pathname.includes('/es') ? '/es' : ''}/getting-started/installation/`;
  }
  if (target === 'home' && url.pathname.startsWith('/next')) {
    url.host = new URL(origins.docs).host;
    return resolve(url);
  }
  if (target === 'home' && /^\/(es\/)?(getting-started|api-reference|internals|reference)\//.test(url.pathname)) {
    url.host = new URL(origins.docs).host;
    return resolve(url);
  }
  const name = decodeURIComponent(url.pathname).replace(/^\//, '');
  const file = [name, `${name}index.html`, `${name}/index.html`, `${name}.html`]
    .find((candidate) => bundles[target].files.has(candidate));
  assert(file, `Missing local destination: ${url.href}`);
  if (url.hash && file.endsWith('.html')) {
    const id = decodeURIComponent(url.hash.slice(1));
    assert(html.get(`${target}/${file}`).includes(`id="${id}"`), `Missing anchor: ${url.href}`);
  }
}

let links = 0;
for (const [key, text] of html) {
  const [target, ...parts] = key.split('/');
  const pathname = `/${parts.join('/').replace(/index\.html$/, '')}`;
  for (const match of text.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
    const url = new URL(match[1].replaceAll('&amp;', '&'), origins[target] + pathname);
    if (!Object.values(origins).includes(url.origin)) continue;
    resolve(url);
    links++;
  }
  // Locale selectors navigate using option values rather than anchor elements.
  for (const match of text.matchAll(/<option[^>]*value="(\/[^\"]*)"/g)) resolve(new URL(match[1], origins[target]));
}
console.log(`Verified ${html.size} HTML assets and ${links} same-site links/assets/anchors`);
