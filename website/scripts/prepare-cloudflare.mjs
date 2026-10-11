import assert from 'node:assert/strict';
import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const output = path.join(dist, 'cloudflare');
const home = 'https://aegisq.dev';
const docs = 'https://docs.aegisq.dev';
const landings = new Set(['index.html', 'es/index.html']);
const sections = ['getting-started', 'api-reference', 'internals', 'reference'];

await readFile(path.join(dist, 'index.html')); // Require a completed Astro build.
await rm(output, { recursive: true, force: true }); // Only owned generated output.

async function files(directory, prefix = '') {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === 'cloudflare') continue;
    const name = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) result.push(...await files(path.join(directory, entry.name), name));
    else {
      assert(entry.isFile(), `Unexpected non-file: ${name}`);
      result.push(name);
    }
  }
  return result.sort();
}

function pagePath(file) {
  return `/${file.replace(/index\.html$/, '')}`;
}

function route(value, file, target) {
  if (!value || value.startsWith('#')) return value;
  const url = new URL(value.replaceAll('&amp;', '&'), docs + pagePath(file));
  if (![home, docs].includes(url.origin)) return value;
  if (url.pathname === '/sitemap-index.xml') return '/sitemap.xml';
  // Assets stay same-origin; both bundles contain their immutable dependencies.
  if (/\.[^/]+$/.test(url.pathname) && !url.pathname.endsWith('.html')) return value;
  const landing = ['/', '/es', '/es/'].includes(url.pathname);
  if (landing && url.pathname === '/es') url.pathname = '/es/';
  const error = /\/404(?:\.html)?\/?$/.test(url.pathname);
  if (error) url.pathname = url.pathname.startsWith('/es/') ? '/es/404/' : '/404.html';
  url.host = new URL(error ? (target === 'home' ? home : docs) : landing ? home : docs).host;
  return url.href.replaceAll('&', '&amp;');
}

function html(source, file, target) {
  // Rewrite only navigation/SEO attributes, never code samples or script text.
  return source.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>|<[^>]+>/g, (tag) => {
    if (/^<(script|style)\b/.test(tag)) return tag;
    return tag.replace(/\b(href|value|content)="([^"]*)"/g, (match, attribute, value) => {
      if (attribute === 'value' && !value.startsWith('/')) return match;
      if (attribute === 'content' && !value.startsWith(docs)) return match;
      const rewritten = route(value, file, target);
      // Starlight assigns option values to location.pathname, not location.href.
      return `${attribute}="${attribute === 'value' ? new URL(rewritten, docs).pathname : rewritten}"`;
    });
  });
}

const sourceFiles = await files(dist);
for (const target of ['home', 'docs']) {
  const directory = path.join(output, target);
  const pages = [];
  for (const file of sourceFiles) {
    if (file.startsWith('sitemap') || file === 'robots.txt') continue;
    const isHtml = file.endsWith('.html');
    const isError = /(?:^|\/)404(?:\/index)?\.html$/.test(file);
    if (isHtml && !isError && (target === 'home') !== landings.has(file)) continue;
    const destination = path.join(directory, file);
    await mkdir(path.dirname(destination), { recursive: true });
    if (isHtml) {
      await writeFile(destination, html(await readFile(path.join(dist, file), 'utf8'), file, target));
      if (!isError) pages.push(file);
    } else await cp(path.join(dist, file), destination);
  }
  // Cloudflare selects the nearest 404.html for the requested path.
  await cp(path.join(directory, 'es/404/index.html'), path.join(directory, 'es/404.html'));
  const origin = target === 'home' ? home : docs;
  const urls = pages.map((file) => {
    const pathname = pagePath(file);
    const alternate = pathname.startsWith('/es/') ? pathname.slice(3) : `/es${pathname}`;
    return `<url><loc>${origin}${pathname}</loc><xhtml:link rel="alternate" hreflang="en" href="${origin}${pathname.startsWith('/es/') ? alternate : pathname}"/><xhtml:link rel="alternate" hreflang="es" href="${origin}${pathname.startsWith('/es/') ? pathname : alternate}"/></url>`;
  });
  await writeFile(path.join(directory, 'sitemap.xml'),
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">${urls.join('')}</urlset>\n`);
  await writeFile(path.join(directory, 'robots.txt'),
    `User-agent: *\nAllow: /\nDisallow: /404\nDisallow: /es/404\nSitemap: ${origin}/sitemap.xml\n`);
  const redirects = target === 'docs'
    ? ['/ /getting-started/installation/ 302', '/es /es/getting-started/installation/ 302', '/es/ /es/getting-started/installation/ 302']
    : sections.flatMap((section) => [
      `/${section}/* ${docs}/${section}/:splat 301`,
      `/es/${section}/* ${docs}/es/${section}/:splat 301`,
    ]);
  await writeFile(path.join(directory, '_redirects'), redirects.join('\n') + '\n');
  await writeFile(path.join(directory, '_headers'),
    '/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n/_astro/*\n  Cache-Control: public, max-age=31536000, immutable\n');
  console.log(`${target}: ${pages.length} indexable pages packaged for ${origin}`);
}
