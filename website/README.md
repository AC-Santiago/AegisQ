# AegisQ Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://rustup.rs/)

Documentation site for **AegisQ** — a post-quantum cryptographic library for Python.

AegisQ combines ML-KEM (FIPS 203) for quantum-resistant key encapsulation with AES-256-GCM for authenticated symmetric encryption. The cryptographic core is written in Rust, exposed to Python via PyO3.

## Quick Start

```bash
# Install dependencies
pnpm install

# Start local dev server at localhost:4321
pnpm dev

# Build for production
pnpm build

# Preview production build locally
pnpm preview
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
│   ├── styles/          # Chromatic Index tokens, themes, and restrained motion
│   ├── content/
│   │   └── docs/        # Markdown/MDX documentation files
│   └── content.config.ts
├── astro.config.mjs      # Starlight configuration
├── package.json
└── tsconfig.json
```

Documentation lives in `src/content/docs/` as `.md` or `.mdx` files. Starlight automatically generates routes from the file structure, matching the sidebar defined in `astro.config.mjs`.

## Frontend design and verification

The Chromatic Index frame keeps Starlight's search, language selector, theme
selector, mobile navigation, and generated contents. It adds localized chapter
navigation and self-hosted Schibsted Grotesk; font sources and the OFL license
are in `public/fonts/`. The library runtime and frontend dependencies are
unchanged.

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
search, language/theme switching, and reduced motion. Reports and screenshots
are development-only artifacts in `../.impeccable/review/` and are not served.
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

## Useful Commands

Cloudflare tooling is pinned in the frontend lockfile. Use
`corepack pnpm install --frozen-lockfile` and `corepack pnpm exec wrangler --version`
from `website/`; do not install a global or unpinned Wrangler. Installing or
checking the CLI does not deploy anything or change the Workers Free plan.

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
