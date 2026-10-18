import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import sharp from 'sharp';
import { buildIcons } from './build-icons.mjs';

const website = fileURLToPath(new URL('../', import.meta.url));
const svg = await readFile(path.join(website, 'public/favicon.svg'), 'utf8');
assert.match(svg, /viewBox="0 0 1440 1440"/);
assert.match(svg, /color="#365d51"/);
assert.match(svg, /prefers-color-scheme: dark/);
assert.match(svg, /:root\s*\{\s*color: #8fc4a8;/);
assert.equal([...svg.matchAll(/<path\b/g)].length, 2, 'Keep both shield and Q tail');
assert(!/DOCTYPE|affinity:|transform=/.test(svg), 'Keep the favicon self-contained');

const generated = await buildIcons();
for (const [name, buffer] of Object.entries(generated)) {
  assert.deepEqual(await readFile(path.join(website, 'public', name)), buffer,
    `${name} is stale; run pnpm icons:build with the frozen lockfile`);
}

async function checkTransparency(image, size) {
  const metadata = await sharp(image).metadata();
  assert.equal(metadata.hasAlpha, true, 'Raster icons must preserve the SVG alpha channel');
  const alpha = await sharp(image).extractChannel('alpha').raw().toBuffer();
  for (const corner of [0, size - 1, size * (size - 1), size * size - 1]) {
    assert.equal(alpha[corner], 0, 'Icon corners must be transparent, not paper-colored');
  }
  assert(alpha.filter((value) => value === 0).length > size * size / 4, 'Keep the transparent canvas and negative space');
  assert(alpha.includes(255), 'The shield must not be blank');
}

const ico = generated['favicon.ico'];
assert.equal(ico.readUInt16LE(0), 0);
assert.equal(ico.readUInt16LE(2), 1);
assert.equal(ico.readUInt16LE(4), 3);
let offset = 6 + 3 * 16;
for (const [index, size] of [16, 32, 48].entries()) {
  const entry = 6 + index * 16;
  assert.equal(ico[entry], size);
  assert.equal(ico[entry + 1], size);
  assert.equal(ico.readUInt16LE(entry + 4), 1);
  assert.equal(ico.readUInt16LE(entry + 6), 32);
  assert.equal(ico.readUInt32LE(entry + 12), offset);
  const length = ico.readUInt32LE(entry + 8);
  const image = ico.subarray(offset, offset + length);
  const metadata = await sharp(image).metadata();
  assert.equal(metadata.format, 'png');
  assert.equal(metadata.width, size);
  assert.equal(metadata.height, size);
  await checkTransparency(image, size);
  offset += length;
}
assert.equal(offset, ico.length, 'ICO offsets cover the entire file');
const apple = await sharp(generated['apple-touch-icon.png']).metadata();
assert.equal(apple.width, 180);
assert.equal(apple.height, 180);
await checkTransparency(generated['apple-touch-icon.png'], 180);

async function files(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await files(file));
    else if (entry.name.endsWith('.html')) result.push(file);
  }
  return result;
}

let pages = 0;
for (const target of ['home', 'docs']) {
  const directory = path.join(website, 'dist/cloudflare', target);
  for (const file of await files(directory)) {
    const relative = path.relative(directory, file).split(path.sep).join('/');
    const base = relative.startsWith('next/') ? '/next/' : '/';
    const html = await readFile(file, 'utf8');
    const head = html.match(/<head>[\s\S]*?<\/head>/)?.[0];
    assert(head, `Missing head in ${file}`);
    const links = [...head.matchAll(/<link\b[^>]*>/g)].map(([tag]) =>
      Object.fromEntries([...tag.matchAll(/([\w-]+)="([^"]*)"/g)].map(([, key, value]) => [key, value])));
    const icons = links.filter(({ rel }) => ['icon', 'shortcut icon', 'apple-touch-icon'].includes(rel));
    assert.deepEqual(icons.map(({ href }) => href), [
      `${base}favicon.ico?v=2`, `${base}apple-touch-icon.png?v=2`, `${base}favicon.svg`,
    ], `Icons must use the channel base, with the SVG preferred last: ${file}`);
    for (const { href } of icons) {
      const pathname = new URL(href, 'https://docs.aegisq.dev').pathname;
      const asset = await readFile(path.join(directory, pathname.slice(1)));
      const name = path.basename(pathname);
      assert.deepEqual(asset, name === 'favicon.svg' ? Buffer.from(svg) : generated[name]);
    }
    assert.match(head, /name="theme-color" content="#365d51"/);
    const mark = html.match(/<span class="aq-site-mark"[^>]*>/)?.[0];
    assert(mark?.includes('aria-hidden="true"'), `Header mark must be decorative: ${file}`);
    assert(mark.includes(`${base}favicon.svg`), `Header mask must use the channel base: ${file}`);
    pages++;
  }
}
assert(pages > 0);
console.log(`PASS: transparent ICO/Apple icons, shield SVG and channel-correct icons/header marks on ${pages} packaged pages (EN/ES, home/docs, stable/next, 404)`);
