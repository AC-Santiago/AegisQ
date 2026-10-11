import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const website = fileURLToPath(new URL('../', import.meta.url));
const sandbox = await mkdtemp(path.join(tmpdir(), 'aegisq-hosting-contract-'));
let checks = 0;

function verify() {
  return execFileSync(process.execPath, [path.join(sandbox, 'scripts/verify-cloudflare.mjs')], { encoding: 'utf8', stdio: 'pipe' });
}

async function rejects(file, mutate, message) {
  const original = await readFile(path.join(sandbox, file), 'utf8');
  await writeFile(path.join(sandbox, file), mutate(original));
  try { assert.throws(verify, message); checks++; }
  finally { await writeFile(path.join(sandbox, file), original); }
}

try {
  await mkdir(path.join(sandbox, 'scripts'));
  for (const file of ['wrangler.home.json', 'wrangler.docs.json', 'scripts/verify-cloudflare.mjs']) {
    await cp(path.join(website, file), path.join(sandbox, file));
  }
  await cp(path.join(website, 'dist/cloudflare'), path.join(sandbox, 'dist/cloudflare'), { recursive: true });
  verify();
  checks++;
  await rejects('wrangler.home.json', (text) => JSON.stringify({ ...JSON.parse(text), main: 'worker.js' }), 'Dynamic Worker must be rejected');
  await rejects('wrangler.docs.json', (text) => JSON.stringify({ ...JSON.parse(text), assets: { directory: './dist/cloudflare/docs', not_found_handling: 'single-page-application' } }), 'SPA fallback must be rejected');
  await rejects('dist/cloudflare/home/index.html', (text) => text.replace('href="https://aegisq.dev/"', 'href="https://docs.aegisq.dev/"'), 'Wrong home recovery/canonical must be rejected');
  await rejects('dist/cloudflare/docs/api-reference/aegiscipher/index.html', (text) => text.replace('value="/es/api-reference/aegiscipher/"', 'value="https://docs.aegisq.dev/es/api-reference/aegiscipher/"'), 'Absolute locale option must be rejected');
  await rejects('dist/cloudflare/docs/es/404.html', (text) => text.replace('content="noindex', 'content="index'), 'Indexable error pages must be rejected');

  // Packaging must not edit executable scripts, styles or code examples.
  for (const [target, file] of [['home', 'index.html'], ['home', 'es/index.html'], ['docs', 'api-reference/aegiscipher/index.html'], ['docs', 'es/api-reference/aegiscipher/index.html']]) {
    const source = await readFile(path.join(website, 'dist', file), 'utf8');
    const packaged = await readFile(path.join(website, 'dist/cloudflare', target, file), 'utf8');
    const immutableBlocks = (text) => [...text.matchAll(/<(script|style|pre)\b[^>]*>[\s\S]*?<\/\1>/g)].map((match) => match[0]);
    assert.deepEqual(immutableBlocks(packaged), immutableBlocks(source), `Immutable content changed: ${file}`);
    checks++;
  }
  console.log(`PASS: ${checks} hosting contract checks (including five negative cases)`);
} finally {
  await rm(sandbox, { recursive: true, force: true }); // Only this test's mkdtemp directory.
}
