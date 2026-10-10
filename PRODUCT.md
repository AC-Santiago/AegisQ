# AegisQ documentation

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The primary audience is Python developers integrating AegisQ. Installation,
working examples, and API lookup take priority. Cryptographic architecture and
security limitations remain available for deeper evaluation.

## Product Purpose

Help developers understand, install, and use AegisQ without overstating its
security properties. The documentation supports both English and Spanish.

## Positioning

AegisQ combines ML-KEM key encapsulation with AES-256-GCM authenticated
encryption through a Python API backed by a Rust core and a PyO3 bridge.
Implementing standardized algorithms does not establish product certification
or an independent security audit.

## Operating Context

Readers move between installation, executable examples, public API signatures,
and security boundaries while integrating the library into Python projects.
`AegisCipher` is the main entry point; `MlKem` serves advanced KEM usage.

## Capabilities and Constraints

- Keep the existing Astro + Starlight documentation application in `website/`
  with its own frontend dependencies, separate from the library runtime.
- Keep `website/src/content/docs/` as the canonical public content source.
- Preserve bilingual routes, existing links, search, theme selection, and
  language switching. Do not change public Python APIs or cryptographic code.
- Prefer static generation and minimal JavaScript. Do not introduce animation
  frameworks merely for decorative effects.
- Preserve historical documentation until a migration plan is approved.
- Hosting/domain and supported-version policy remain open decisions.

## Brand Commitments

Keep the AegisQ name. The requested interface is modern and minimalist, with
smooth, restrained motion and a premium feel. Avoid cybersecurity clichés,
generic SaaS styling, and unverified promotional claims.

## Evidence on Hand

- Canonical bilingual guides and API references: `website/src/content/docs/`.
- Public API and implementation: `aegisq/`, `crates/aegisq-core/`, and
  `crates/aegisq-pyo3/`.
- Tests and vector fixtures: `tests/python/` and Rust module tests.
- Release history and security policy: `CHANGELOG.md` and `SECURITY.md`.
- No independent audit, certification, customer proof, or performance result
  may be invented to support the visual design.

## Product Principles

1. Make the first successful integration easy to find.
2. Keep technical truth and limitations visible.
3. Preserve reading comfort and familiar documentation controls.
4. Maintain equivalent paths for English and Spanish readers.

## Accessibility & Inclusion

Target WCAG 2.2 AA; verify keyboard navigation, visible focus, contrast,
responsive layout, both themes, and reduced-motion behavior. A target is not
a claim of completed accessibility conformance.
