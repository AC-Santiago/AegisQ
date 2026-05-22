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
├── src/
│   ├── assets/          # Images used in docs
│   ├── content/
│   │   └── docs/        # Markdown/MDX documentation files
│   └── content.config.ts
├── astro.config.mjs      # Starlight configuration
├── package.json
└── tsconfig.json
```

Documentation lives in `src/content/docs/` as `.md` or `.mdx` files. Starlight automatically generates routes from the file structure, matching the sidebar defined in `astro.config.mjs`.

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
