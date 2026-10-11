import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { channels, documentationPath } from '../src/docs-channels.mjs';

assert.match(channels.stable.version, /^\d+\.\d+\.\d+$/);
assert.equal(channels.stable.ref, `v${channels.stable.version}`);
for (const file of ['pyproject.toml', 'crates/aegisq-core/Cargo.toml', 'crates/aegisq-pyo3/Cargo.toml']) {
  const manifest = await readFile(`../${file}`, 'utf8');
  assert.equal(manifest.match(/^version = "([^"]+)"/m)[1].replace(/-?rc/, '-rc'), channels.next.version);
}
for (const path of ['/api-reference/aegiscipher/', '/es/api-reference/aegiscipher/']) {
  assert.equal(documentationPath(path, 'next'), `/next${path}`);
  assert.equal(documentationPath(`/next${path}`, 'stable'), path);
  assert.equal(documentationPath(`/next${path}`, 'next'), `/next${path}`);
}
const invalid = spawnSync(process.execPath, ['--input-type=module', '-e', "import './src/docs-channels.mjs'"], {
  env: { ...process.env, AEGISQ_DOCS_CHANNEL: 'toString' }, encoding: 'utf8',
});
assert.notEqual(invalid.status, 0);
assert.match(invalid.stderr, /Unknown documentation channel/);
const rewritten = spawnSync(process.execPath, ['--input-type=module', '-e', `
  import { remarkChannelLinks } from './src/docs-channels.mjs';
  const tree = { children: [
    { type: 'link', url: '/api-reference/aegiscipher/#generate_keypair' },
    { type: 'definition', url: '/es/api-reference/keypair/' },
    { type: 'code', value: '/api-reference/aegiscipher/' },
    { type: 'link', url: 'https://pypi.org/project/aegisq-pqc/' },
  ] };
  remarkChannelLinks()(tree); console.log(JSON.stringify(tree.children));
`], { env: { ...process.env, AEGISQ_DOCS_CHANNEL: 'next' }, encoding: 'utf8' });
assert.equal(rewritten.status, 0);
assert.deepEqual(JSON.parse(rewritten.stdout), [
  { type: 'link', url: '/next/api-reference/aegiscipher/#generate_keypair' },
  { type: 'definition', url: '/next/es/api-reference/keypair/' },
  { type: 'code', value: '/api-reference/aegiscipher/' },
  { type: 'link', url: 'https://pypi.org/project/aegisq-pqc/' },
]);

async function pages(directory, prefix = '') {
  const result = [];
  for (const entry of await readdir(directory + prefix, { withFileTypes: true })) {
    const file = prefix + entry.name;
    if (entry.isDirectory() && entry.name !== '_next') result.push(...await pages(directory, file + '/'));
    else if (/\.(md|mdx)$/.test(file) && !/(^|\/)index\./.test(file)) result.push(file.replace(/\.(md|mdx)$/, '/index.html'));
  }
  return result;
}
const files = await pages('src/content/docs/');
assert.equal(files.length, 36);
for (const file of files) {
  const stable = await readFile(`dist/cloudflare/docs/${file}`, 'utf8');
  const next = await readFile(`dist/cloudflare/docs/next/${file}`, 'utf8');
  assert.match(stable, /data-doc-channel="stable"/);
  assert.match(next, /data-doc-channel="next"/);
  assert(next.includes(`rel="canonical" href="https://docs.aegisq.dev/next/${file.replace(/index\.html$/, '')}"`));
  for (const text of [stable, next]) {
    assert(text.includes(`value="/${file.replace(/index\.html$/, '')}"`));
    assert(text.includes(`value="/next/${file.replace(/index\.html$/, '')}"`));
  }
  assert.match(next, /name="robots" content="noindex, follow"/);
  assert(!/name="robots" content="noindex/.test(stable));
  if (file.includes('getting-started/installation/')) {
    assert(stable.includes(`--branch ${channels.stable.ref}`));
    assert(next.includes('--branch develop'));
    assert(!next.includes(`--branch ${channels.stable.ref}`));
  }
}
const sitemap = await readFile('dist/cloudflare/docs/sitemap.xml', 'utf8');
assert(!sitemap.includes('/next/'));
assert.equal((sitemap.match(/<loc>/g) || []).length, 36);
console.log('PASS: 36 bilingual stable/next page pairs, channel paths, overrides, SEO and manifest guards');
