import { spawnSync } from 'node:child_process';
import { cp, rm } from 'node:fs/promises';
import { channels } from '../src/docs-channels.mjs';

for (const channel of Object.keys(channels)) {
  const result = spawnSync(process.execPath, ['node_modules/astro/bin/astro.mjs', 'build'], {
    stdio: 'inherit', env: { ...process.env, AEGISQ_DOCS_CHANNEL: channel },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
await rm('dist/next', { recursive: true, force: true }); // Owned generated output only.
await cp('dist-next', 'dist/next', { recursive: true });
// Development has documentation, not another homepage or sitemap.
for (const file of ['index.html', 'es/index.html', 'sitemap-index.xml', 'sitemap-0.xml']) {
  await rm(`dist/next/${file}`, { force: true });
}
