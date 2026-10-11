# AegisQ Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)

Documentation site for **AegisQ** — a post-quantum cryptographic library for Python.

Published homepage: https://aegisq.dev · Documentation: https://docs.aegisq.dev

The sites use Cloudflare Workers Static Assets and Custom Domains on Workers
Free. Cloudflare manages DNS/TLS; the VPS is a build/deployment client, not an
origin. GitHub CI validates changes but **does not publish them**.

AegisQ combines ML-KEM (FIPS 203) for quantum-resistant key encapsulation with AES-256-GCM for authenticated symmetric encryption. The cryptographic core is written in Rust, exposed to Python via PyO3.

## Quick Start

From the repository root:

```bash
cd website

# Install dependencies
corepack pnpm install --frozen-lockfile

# Start local dev server at localhost:4321
corepack pnpm dev

# Build for production
corepack pnpm build

# Preview production build locally
corepack pnpm preview
```

## Project Structure

```
website/
├── public/              # Static assets (favicon, etc.)
├── scripts/             # Reusable browser verification (local reports are ignored)
├── src/
│   ├── assets/          # Images used in docs
│   ├── components/      # Native Starlight wrappers and accessibility enhancements
│   ├── pages/           # Custom bilingual 404 routes using the Starlight shell
│   ├── scripts/         # Progressive reading-motion enhancement
│   ├── styles/          # Paper/forest tokens, themes, and restrained motion
│   ├── content/
│   │   └── docs/        # Markdown/MDX documentation files
│   └── content.config.ts
├── astro.config.mjs      # Starlight configuration
├── package.json
└── tsconfig.json
```

Documentation lives in `src/content/docs/` as `.md` or `.mdx` files. Starlight automatically generates routes from the file structure, matching the sidebar defined in `astro.config.mjs`.

## Documentation channels

The version selector offers only the latest stable release and development,
in English and Spanish. There are no historical documentation archives.

| Channel | Source | Public paths |
| --- | --- | --- |
| Stable | Reviewed stable-compatible `src/content/docs/` pages | Existing paths, including `/es/` |
| Development | Same baseline with `_next/` page overrides | `/next/`, including `/next/es/` |

`src/docs-channels.mjs` records the published stable version/tag and development
version/branch. A checkout prerelease is **not** proof of a published stable
release. Update stable metadata only after verifying the actual PyPI release;
update both stable installation examples and EN/ES content together. The build
checks the development label against `pyproject.toml`; it does not publish a
package or automatically query PyPI.

Stable pages may receive documentation corrections without importing development
API changes. For development-only changes, add a full replacement page at
`src/content/docs/_next/<same-path>` and its `es/` counterpart. Unchanged pages
inherit the stable baseline; this avoids duplicate maintained copies of identical
contracts. The initial shared baseline was checked against `v1.5.0`: Python/Rust
runtime sources match the development checkout, apart from version metadata.
Adding a new override file requires restarting the local dev server.

`pnpm build` builds both channels with separate Astro caches and Pagefind indexes,
then assembles them under `dist/`. Preview that output to test channel switching.
`pnpm dev` shows stable; `AEGISQ_DOCS_CHANNEL=next pnpm dev` shows development at
`/next/`. Internal prose links, native sidebar, language/theme selectors and
search stay in the chosen channel. The version selector retains page, language
and fragment; fallback links are available without JavaScript. Both channels
recover the existing localized homepage, not a duplicate development homepage.

Development pages carry a prerelease notice and `noindex, follow`, and are omitted
from the production sitemap. Their own Pagefind index remains searchable.
`scripts/test-doc-channels.mjs` checks page pairs, selector destinations,
installation overrides, SEO and version metadata after packaging. The hosting
browser checks exercise channel round trips, isolated search and native locale
controls. Publication remains manual with separate approval.

## Frontend design and verification

The paper/forest frame keeps Starlight's search, language selector, theme
selector, mobile navigation, and generated contents. It adds localized chapter
navigation and self-hosted Schibsted Grotesk; font sources and the OFL license
are in `public/fonts/`.

The shared theme lives in `src/styles/docs.css`. A small
`src/scripts/reading-motion.ts` enhancement uses one IntersectionObserver for
one-shot entrances as headings, code, lists, tables and asides enter the viewport.
Prose remains still. Home columns arrive from shallow perspective with a bounded
stagger; offscreen blocks remain fully visible while waiting. Reduced motion,
missing JavaScript or IntersectionObserver, deep links, keyboard focus and print
retain readable content. There are no animation dependencies or scroll listeners.
The other custom client script synchronizes the native mobile menu's expanded
state onto its actual button for assistive technology. Error pages also normalize
native language-selector destinations to the generated EN/ES 404 routes.

The English and Spanish home pages use a shared `LandingHero.astro` on
Starlight's splash template. Their Reading desk layout and packet figure are
styled in `src/styles/landing.css`; shared motion lives in `docs.css`. The documentation
sidebar and chapter band remain unchanged on reference pages. No client-side
animation library or new dependency is required.

The masthead shows only AegisQ on the homes. The optional Documentation /
Documentación sub-label is rendered on documentation routes, not on splash
pages. The home Hero override matches the actual home pathname. A shared
`NotFoundHero.astro` renders the bilingual custom error pages from
`src/pages/404.astro` and `src/pages/es/404.astro`, using the native Starlight page
shell: large 404, a clear explanation, home/docs recovery links and native
search/theme/language controls. Error pages are excluded from search and carry
`noindex`. Starlight's default 404 injection is disabled to avoid duplicate
routes. The generated fallback is `/404.html`; the Spanish route is
`/es/404/`. Hosting must serve `404.html` with HTTP 404 for unknown
paths, rather than redirecting those paths to the home page.

Run `pnpm build` and `pnpm astro check`, then test the **production preview**
(not the dev server) to exercise the generated Pagefind search index. Browser
smoke checks are in `scripts/verify-ui.mjs`; from the repository
root, with an already available Playwright module and Chromium executable:

```bash
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
CHROMIUM_PATH=/absolute/path/to/chromium \
node website/scripts/verify-ui.mjs
```

The checks cover the bilingual overview and AegisCipher pages at 375, 768, 1024,
and 1440 pixels in both themes, plus keyboard navigation, mobile menu state,
icon centering in both open/closed states, the 44px menu target, the 799/800px
mobile breakpoint, desktop menu visibility, search, language/theme switching,
and reduced motion. Reports and screenshots are development-only artifacts in
`../.impeccable/review/` and are not served.
No browser or package is installed by this script. This smoke matrix is not a
full accessibility audit or a cross-browser conformance claim.

Run `website/scripts/verify-landing.mjs` with the same environment variables
from the repository root for the landing matrix: both homes at 320, 375, 768,
1024, and 1440 pixels in both themes, plus both AegisCipher pages at mobile and
desktop widths. It checks the packet order, localized entry links, single H1,
native docs navigation, keyboard entry, and soft/reduced motion. Follow it with
`UI_INTERACTIONS_ONLY=1` on `verify-ui.mjs` for the existing native-control checks.
Run `website/scripts/verify-motion.mjs` with the same environment for actual entrance events on
both homes and both AegisCipher routes in light/dark at desktop/mobile widths.
It also checks once-only playback, visible waiting content, reduced-motion and
no-JavaScript/no-IntersectionObserver fallbacks, deep links, keyboard focus,
dynamic motion preference and the custom 404 surface.
Run `website/scripts/verify-404.mjs` for the error-page matrix, native locale/theme
switching, home recovery, noindex and the production preview's unknown-route
HTTP 404 response. `UI_QA_DIR` can override the ignored local report directory.

## Split-domain production bundles

Run these commands from `website/`:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm astro check
corepack pnpm build:cloudflare
corepack pnpm exec wrangler deploy --config wrangler.home.json --dry-run --outdir .wrangler/dry-home
corepack pnpm exec wrangler deploy --config wrangler.docs.json --dry-run --outdir .wrangler/dry-docs
```

These checks make no Cloudflare changes. The generated `dist/cloudflare/home`
serves only the English/Spanish homes at `aegisq.dev`; `dist/cloudflare/docs`
serves 36 stable and 36 development pages at `docs.aegisq.dev`. Both carry local fonts,
scripts and the bilingual Pagefind index. Home search results use legacy-path
redirects to the documentation host; no cross-origin search fetch is required.
The packaging step rewrites navigation, locale options and SEO attributes,
not examples or application scripts, and produces host-specific sitemaps/robots.
Docs roots temporarily redirect to localized installation pages. Unknown routes
use the nearest English/Spanish `404.html` with HTTP 404, not SPA fallback.

Only static assets are configured: no Worker script, bindings, SSR or paid
resources. The verifier rejects unexpected config fields and checks Workers
Free limits (20,000 files and 25 MiB per asset). It does not inspect account
billing; confirm Workers Free before an approved production deployment. Removing
the local packaging scripts/configs does not roll back an existing deployment
or its DNS bindings.

Cloudflare tooling is pinned in the frontend lockfile. Use
`corepack pnpm install --frozen-lockfile` and `corepack pnpm exec wrangler --version`
from `website/`; do not install a global or unpinned Wrangler. Installing or
checking the CLI does not deploy anything or change the Workers Free plan.

## Hosting runtime checks and publication gate

After `build:cloudflare`, run `corepack pnpm verify:hosting`. It starts/stops two
owned local Wrangler emulators on ports 4351/4352 and checks redirects, localized
HTTP 404, search assets and headers. It never contacts production hosts. For
Chromium checks, provide an already installed Playwright module and browser:

```bash
HOSTING_BROWSER=1 PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
CHROMIUM_PATH=/absolute/path/to/chromium corepack pnpm verify:hosting
```

Run `node scripts/test-cloudflare.mjs` for isolated contract tests: invalid
dynamic/SPA configs, wrong canonical/home links, absolute locale values and
indexable errors must fail, while scripts/styles/code samples remain unchanged.

The browser gate checks both locales at mobile/desktop widths, home search
results reaching docs, native locale/theme controls and recovery to the correct
home. Reports are ignored under `.impeccable/review/hosting`. The separate Website
workflow runs builds, dry-runs and this gate on PRs/pushes; it has read-only GitHub
permissions and no Cloudflare credentials or deploy job. It does not replace the
library's CI or claim a full accessibility/cross-browser audit.

### Update the published sites

Production updates require separate approval. Merge reviewed changes through
`develop` and promote them to `main`; build from that reviewed source. Confirm
Workers Free, the correct account, the active `aegisq.dev` zone and the expected
existing DNS/Worker domain bindings before writing anything. Keep scoped
authentication outside Git. Use device authorization on a headless VPS; never
paste tokens into chat or commit them.

After the build, contract tests, dry-runs and runtime checks above pass, deploy
from `website/` in this order:

```bash
corepack pnpm exec wrangler deploy --config wrangler.docs.json
# Verify docs HTTPS, redirects, bilingual search, theme/locale controls and HTTP 404.
# Continue only after documentation verification passes.
corepack pnpm exec wrangler deploy --config wrangler.home.json
# Verify the same home checks and navigation between both live hosts.
```

Custom Domains manage DNS/TLS; do not replace expected bindings or unrelated DNS
records blindly. No PyPI tag or library version bump is required for a docs update.
Cloudflare may inject its Web Analytics beacon into live HTML; distinguish that
edge behavior from authored assets when comparing content. Local emulators do
not establish live DNS/TLS or account billing state.

The two deployments are not atomic. Record each Worker's previous deployment
before updating. On a partial failure, stop and report which host changed; use
that Worker's previous deployment for rollback. A newly created Worker has no
previous version to restore: report the partial state instead of claiming a
rollback succeeded. Do not delete Workers or DNS records without approval.

## Useful Commands

| Command              | Action                                       |
| :------------------- | :------------------------------------------- |
| `pnpm dev`           | Start local dev server at `localhost:4321`   |
| `pnpm build`         | Build production site to `./dist/`           |
| `pnpm preview`       | Preview built site locally before deploying  |
| `pnpm astro check`   | Type-check the Astro project                 |
| `pnpm astro add <pkg>` | Add an integration (e.g., sitemap)          |

## Resources

- [AegisQ on PyPI](https://pypi.org/project/aegisq-pqc/) — Install via pip or uv
- [AegisQ on GitHub](https://github.com/AC-Santiago/AegisQ/) — Source code, issues, PRs
- [FIPS 203 (ML-KEM Standard)](https://csrc.nist.gov/pubs/fips/203/final) — NIST specification
- [Starlight Docs](https://starlight.astro.build/) — Astro documentation theme docs
