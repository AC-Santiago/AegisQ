---
name: AegisQ documentation
description: Post-Quantum Cryptography for Python — ML-KEM (FIPS 203) + AES-256-GCM. Bilingual Starlight site; reference-paper light theme and charcoal/green dark theme on a self-hosted Schibsted Grotesk frame.
colors:
  paper: "#f7f9f8"
  white: "#ffffff"
  ink: "#1c302b"
  forest: "#315e50"
  moss: "#4d625a"
  fog: "#edf2ef"
  rule: "#c0d0c7"
  rule-strong: "#789388"
  night: "#17231e"
  night-raised: "#1d2d25"
  night-soft: "#24392e"
  silver: "#e7eee9"
  sage: "#b7cbbd"
  mint: "#a6cfb8"
  night-rule: "#40574a"
  night-rule-strong: "#769881"
  selection-light: "#c2d9cc"
typography:
  body:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontWeight: 400
    lineHeight: 1.75
  body-muted:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontWeight: 400
    fontSize: "0.875rem"
  display:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontSize: "clamp(2.25rem, 4vw, 3.5rem)"
    fontWeight: 600
    letterSpacing: "-0.035em"
    lineHeight: 1.2
  headline:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontSize: "1.625rem"
    fontWeight: 600
    letterSpacing: "-0.015em"
  title:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    letterSpacing: "-0.015em"
  label:
    fontFamily: "Schibsted Grotesk, sans-serif"
    fontWeight: 600
    letterSpacing: "0"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.875rem"
rounded:
  md: "0.375rem"
  xs: "0.2rem"
spacing:
  1: "0.5rem"
  2: "1rem"
  3: "1.5rem"
  4: "2rem"
components:
  aq-actions-primary:
    backgroundColor: "{colors.forest}"
    textColor: "{colors.white}"
    rounded: "{rounded.md}"
    padding: "0.625rem 1rem"
  aq-actions-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.forest}"
    rounded: "{rounded.md}"
    padding: "0.625rem 1rem"
  aq-chapter-link:
    backgroundColor: "{colors.forest}"
    textColor: "{colors.white}"
    rounded: "0"
    padding: "0.5rem 0.125rem"
  aq-sidebar-link-current:
    backgroundColor: "{colors.selection-light}"
    textColor: "{colors.forest}"
    rounded: "{rounded.md}"
    padding: "0.5rem 0.75rem"
  aq-brand-wordmark:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "0"
    padding: "0"
  aq-search-trigger:
    rounded: "{rounded.md}"
  aq-mobile-menu:
    rounded: "{rounded.md}"
    width: "2.75rem"
    height: "2.75rem"
  aq-code-block:
    rounded: "{rounded.md}"
---

# Design System: AegisQ documentation

## Overview

**Creative North Star: "The Reference Library on Forest Paper."**

AegisQ's documentation reads as a calm technical reference. On every documentation page: a thin two-tier header (paper masthead over a forest-green chapter band), a slim sidebar of section headings, and a single reading column set to a comfortable 75ch measure. Depth comes from paper tint, hairline rules, and tonal banding rather than from offset shadows on the custom frame. The two bilingual home routes (`/`, `/es/`) override the splash template only: they keep the same paper-and-forest world, the same masthead (with the native theme and language selects rearranged onto a second row below `49.99rem`, not duplicated), and the same Schibsted Grotesk workhorse family, but they widen the content frame to `82rem` and lay a three-column reading desk above a canonical Transit Package diagram.

Below `49.99rem` the desk collapses to a single reading column; at or below `74rem` the desk uses two columns and the entry-paths row spans the full width beneath. Native Starlight controls are kept and styled, never replaced; the small observer that mirrors `aria-expanded` onto the native menu button continues to ship. `LandingHero.astro` uses the reading desk only on the actual home paths. Error entries use `NotFoundHero.astro`; other splash entries retain the native Hero.

Motion pairs a shallow back-to-front home arrival (`640ms`, at most `140ms` stagger) with quiet one-shot reading-block entrances (`320ms`) while scrolling. Docs retain their `420ms` title settle; controls retain `160ms` color transitions. Content is visible before enhancement; reduced motion removes every animation and transition. PRODUCT.md supplies the cryptographic and product commitments; this document records the visual system only.

**Key Characteristics:**

- Two-tier native shell on docs: a paper masthead with the brand and a forest-green chapter band across the full width. On splash routes the chapter band is omitted by `DocsHeader.astro` (`template !== 'splash'` guard).
- Single reading column at `48rem` on docs with paragraph measure capped at `75ch` for body text; splash routes widen the content frame to `82rem` and lay a `1.08fr / 1.42fr / 0.5fr` three-column desk above the canonical Transit Packet figure.
- Predominantly flat custom frame: paper tint, hairline rules, and tonal banding carry structure; only one custom `box-shadow` rule exists (action-button hover).
- Schibsted Grotesk for reading; system monospace stack for code. No second reading family, no display face, no icon font.
- Native Starlight controls (search, theme, language, mobile menu) styled, never duplicated, on both routes.
- Home columns arrive from shallow perspective; headings and structural blocks enter once as they come into view. Prose stays still, navigation is never animated, and reduced-motion users receive no entrances.

## Colors

The palette is a small set of paper, ink, and forest hues that share hue and chroma. The light theme is a reference paper with deep green type and a forest chapter band; the dark theme keeps the same green hierarchy on charcoal paper. Hex values below are the canonical primitives shipped in `website/src/styles/docs.css`; semantic roles are aliases on top of them.

### Primary

- **Forest** (`#315e50`): chapter-band background, the light-theme accent for the current sidebar item, and the primary action button on the home pages. The chapter band is the only fully saturated surface in the system; everything else is paper, ink, or fog.
- **Mint** (`#a6cfb8`): the dark-theme accent. It plays the same role as Forest in the dark theme — current sidebar text, primary action button, focus ring — desaturated enough to sit on charcoal without glowing.

### Secondary

- **Ink** (`#1c302b`): body and heading text on the light theme. A muted near-black with green in the hue; it never reads as pure black on paper.
- **Silver** (`#e7eee9`): body text on the dark theme. The same near-black relationship inverted: a tinted off-white that stays legible on charcoal without going stark.

### Tertiary

- **Moss** (`#4d625a`): muted body text, intros, and code-block captions on the light theme. Reads as faded ink.
- **Sage** (`#b7cbbd`): the dark-theme counterpart to Moss, used for muted text and the chapter-band scrollbar.

### Neutral

- **Paper** (`#f7f9f8`): the light-theme canvas behind every page. A faintly green-tinted near-white.
- **White** (`#ffffff`): the light-theme surface (masthead, code panels). Sits one step brighter than Paper to lift content off the page.
- **Fog** (`#edf2ef`): the light-theme soft surface for table headers and the sidebar background. Secondary action buttons stay transparent.
- **Night** (`#17231e`): the dark-theme canvas.
- **Night-Raised** (`#1d2d25`): the dark-theme surface (sidebar, masthead).
- **Night-Soft** (`#24392e`): the dark-theme soft surface (table headers, sidebar background tint).
- **Rule** (`#c0d0c7`): light-theme hairline borders and dividers between sections.
- **Rule-Strong** (`#789388`): light-theme input borders, button borders, sidebar active-page outline.
- **Night-Rule** (`#40574a`): dark-theme hairlines; the dark-theme background of the current sidebar link.
- **Night-Rule-Strong** (`#769881`): dark-theme input borders and active surfaces.
- **Selection-Light** (`#c2d9cc`): the light-theme selection background and the light-theme background of the current sidebar link. Sits between Paper and Forest.

### Named Rules

**The Forest-on-Paper Rule (docs).** Forest fills the chapter band on documentation pages and the light-theme primary action on every route. It also colors links, focus rings, and current docs sidebar text. Keep the reading ground neutral rather than extending the band color behind prose. The chapter band is intentionally absent on splash routes — that absence is part of the world, not a defect.

**The Ink-Silver Swap.** Body text color is Ink on light and Silver on dark; muted text is Moss and Sage respectively. Never pair dark-theme text against light-theme surfaces or vice versa. The two themes are mirror palettes, not recolors. This applies on both routes; the landing h1 sits on the canvas in `--aq-text` (Ink / Silver), not in Forest.

**The Current Sidebar Reads Forest, Not Fills Forest (docs).** On the light theme, the active docs sidebar link uses Selection-Light as a background tint and Forest as the text color — Forest is the voice, not the wall. On the dark theme, Night-Rule is the background and Mint is the text. The sidebar never paints a Forest block. The landing route has no sidebar.

**The Home-Scoped Hero Rule.** The reading desk is rendered only on splash routes whose pathname matches the locale's home link (`/`, `/es/`). Error entries use the custom recovery surface; other splash routes retain the native Hero. The landing is **not** a generic centered hero, not a marketing band, not a decorative gradient. Its accent uses are restricted to: the second line of the h1 (`--aq-accent` color, plain — never italic), the Open-docs CTA fill, and the first cell of the Transit Packet figure.

**The Packet Excerpted, Not Proportional Rule.** The Transit Packet figure renders four cells in equal-width columns regardless of byte size (ML-KEM capsule 768/1088/1568 B, AES nonce 12 B, auth tag 16 B, ciphertext variable). Only the first cell (capsule) carries the accent background; cells 2–4 use the soft surface. The caption states the figure is not to scale.

## Typography

**Display Font:** Schibsted Grotesk (with `sans-serif` fallback)
**Body Font:** Schibsted Grotesk (with `sans-serif` fallback)
**Label/Mono Font:** System monospace stack (`ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`) for inline code and code blocks

**Character:** One humanist sans family with weight as the only differentiator. Headings and body share the same letterforms; size, weight, and tight tracking do all the typographic work. Tracking tightens (-0.035em on h1, -0.015em on h2/h3/h4) to keep long headings balanced. Heading line-height inherits the native `--sl-line-height-headings: 1.2`; body line-height is the native `--sl-line-height: 1.75`.

### Hierarchy

- **Display — docs** (600, `clamp(2.25rem, 4vw, 3.5rem)`, 1.2 inherited, -0.035em): the page H1 only on docs.
- **Display — landing** (600, `clamp(2.75rem, 4.2vw, 3.75rem)`, line-height `1.04`, -0.04em): the splash h1 only. On mobile (`≤ 49.99rem`) it scales with `clamp(2.5rem, 8.5vw, 3.75rem)` and caps at `16ch`. The second line is a plain (non-italic) `span` colored `--aq-accent`.
- **Headline** (600, `1.625rem`, -0.015em): H2 section headings inside a page.
- **Title** (600, `1.25rem`, -0.015em): H3 sub-sections.
- **Body** (400, inherited, 1.75): running prose. Paragraphs and list items cap at `max-width: 75ch` on docs.
- **Body — landing intro paragraph** (400, `1rem`, line-height `1.7`): capped at `max-width: 38ch` on desktop and `max-width: 65ch` on mobile (`≤ 49.99rem`). Color `--aq-text-muted`.
- **Muted** (400, `0.875rem`): intros, captions, table cells, navigation links, and the brand sub-label.
- **Label** (600, `0.875rem`): the sidebar group labels (`.sidebar-content .large`) and the action buttons. The brand wordmark itself is set at `1.5rem` and is recorded separately under the Brand wordmark component.
- **Packet caption** (500, `1.125rem`, -0.015em): the splash `figcaption` above the Transit Packet figure.
- **Packet strong / cell label** (600, `0.9375rem`, 1.5): the cell name inside `.aq-packet-parts`.
- **Packet span / cell detail** (400, `0.8125rem`, 1.5, `--aq-text-muted`): the cell detail (e.g. `12 bytes`); inherits color on the first (accented) cell.
- **Example heading** (600, `1rem`, -0.015em): the splash `.aq-example h2`.
- **Example sub-heading** (500, `0.9375rem`): the splash `.aq-example h3`.
- **Code** (system mono, `0.875rem`): inline `code` (radius `0.2rem`) and code blocks (radius `0.375rem`).

### Named Rules

**The One-Family Rule (reading type).** Schibsted Grotesk is the only reading face. There is no display serif, no second sans for labels. The system monospace stack is reserved for code; it is not used for labels, captions, or headings.

**The 75ch Measure.** Body paragraphs and list items on docs are capped at `max-width: 75ch`. The landing splash routes cap their body text at `38ch` (introduction paragraph on desktop) and `65ch` (introduction paragraph on mobile); the landing `.aq-roundtrip-context` trust paragraph caps at `75ch`. Code blocks, tables, and the navigation shell are exempt because they carry structure, not reading flow.

**The Plain Accent, No Italic Rule.** On the landing h1, the second line is a `span` colored `--aq-accent`; weight, tracking, and family are inherited from the parent h1. **The accent is never italic** — no `font-style: italic` is declared in `landing.css` or in the reference `.aq-introduction h1 span`. Production headings across every route remain upright.

## Layout

The system is a single reading column with a thin sidebar on docs, framed by the two-tier native shell; the two splash routes (`/`, `/es/`) widen the content frame and lay a three-column reading desk above the canonical Transit Packet figure. All values below are the canonical primitives shipped in `website/src/styles/docs.css` and `website/src/styles/landing.css`; no measurement here is aspirational.

### Docs container and grid

- **Sidebar width:** `15.25rem` (`--sl-sidebar-width`, an explicit override of Starlight's native `18.75rem`).
- **Content width:** `48rem` (`--sl-content-width`).
- **Sidebar padding-top:** `1.5rem` (the `--aq-space-3` token).
- **Content-panel padding-block:** `2rem` (top and bottom) below `50rem`. At `50rem` and up, padding-block-start becomes `2.5rem`; padding-block-end stays `2rem`.
- **Horizontal content padding:** `clamp(1.125rem, 3vw, 2.75rem)` (`--sl-content-pad-x`).
- **Scroll padding:** `var(--sl-nav-height) + var(--sl-mobile-toc-height) + 1rem`, so anchor links land below the masthead + chapter band.

### Landing (splash) container and grid

- **Content width:** `82rem` (`--sl-content-width` override scoped to `:root:has(.aq-landing)`); the splash routes read at this wider frame only.
- **Desk column template:** `minmax(0, 1.08fr) minmax(0, 1.42fr) minmax(0, 0.5fr)` — three unequal columns for introduction+CTA, working code, and entry paths respectively. This is the base rule (no media wrap).
- **Desk gap:** `var(--aq-landing-gap)` = `clamp(1.5rem, 3vw, 2.5rem)`.
- **Desk vertical padding:** `clamp(0.75rem, 2vw, 1.5rem)` top, `2.5rem` bottom.
- **Splash-only overrides on `:root:has(.aq-landing)`:** `--sl-nav-height` collapses to `var(--aq-masthead-height)` (no chapter band on splash); the markdown content border-top and `2.5rem` padding-top apply to the body sections that follow the landing (Find Your Workflow etc.).

### Shell heights

- **Masthead height (docs):** `3.75rem` below `50rem`, `4.5rem` at `50rem` and up. The masthead holds the brand, the native search button, the theme and language selects, and the native mobile-menu trigger.
- **Masthead height (landing):** same `3.75rem` / `4.5rem` breakpoints above `49.99rem`; **at or below `49.99rem` the landing-only override raises it to `7rem`** so the masthead can fit a two-row layout (brand + menu on row 1, native theme and language selects on row 2).
- **Chapter-band height:** `2.75rem` below `50rem`, `3rem` at `50rem` and up. The band sits directly under the masthead with no gap and no border between them. **The chapter band is not rendered on splash routes** (`DocsHeader.astro` skips it when `template === 'splash'`); therefore `--sl-nav-height` on splash equals `--aq-masthead-height` only.
- **Starlight nav height:** `masthead + chapter-band` on docs; `masthead` only on splash. Exposed as `--sl-nav-height` so the rest of the shell aligns with the local total.
- **Mobile menu button size:** `2.75rem` (`--sl-menu-button-size`).

### Landing masthead — two-row mobile (≤ 49.99rem, splash only)

- **Masthead height:** `7rem`.
- **Native `.header`** is set to `display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0.25rem 1rem` so the brand wordmark and the mobile-menu button share row 1.
- **Native `.right-group`** (theme and language selects) flows onto row 2 via `grid-column: 1 / -1; justify-content: flex-end`. **No new control instances are added.** No new JavaScript is shipped.
- **Native `.social-icons`** are hidden on landing mobile (row 2 is reserved for the theme and language selects).
- The small observer that mirrors `aria-expanded` onto the native mobile-menu button continues to ship unchanged.

### Desk responsive behavior (splash only)

The three-column reading rule is the unprefixed base. Two media queries refine it. **Boundary semantics:** `@media (max-width: …)` in CSS is inclusive of the listed width, so the layered rules resolve as follows:

- **Three columns (`1.08fr / 1.42fr / 0.5fr`)** apply at viewport-width strictly **greater than `74rem`** (the base rule; the `max-width: 74rem` override is inclusive and overrides it at exactly `74rem`).
- **Two columns (`0.9fr / 1.1fr`)** apply at `49.99rem < viewport-width ≤ 74rem`. The `.aq-entry-paths` block becomes a full-width row beneath with a top hairline (`border-top: 1px solid var(--aq-border)`) instead of the inline-start rule, and `.aq-roundtrip-context` stacks vertically.
- **Single column (`1fr`)** apply at viewport-width ≤ `49.99rem`. The packet grid stacks vertically (one cell per row, hairline between cells, no inline-end border), the h1 caps at `16ch` and scales with `clamp(2.5rem, 8.5vw, 3.75rem)`, the intro paragraph widens to `65ch`, and the entry-paths row drops its top hairline and stacks its links with `0.625rem` vertical padding.

### Docs responsive behavior

- Below `50rem`: chapter-band links are `0.875rem` and the masthead is shorter; the chapter band becomes horizontally scrollable.
- `50rem` and up: masthead and chapter band grow slightly, action-button row breathes, content-panel padding-top becomes `2.5rem`.
- `64rem` and up: the brand sub-label ("Documentation" / "Documentación") appears on documentation routes only. Homes and other splash pages do not render it.

### Spacing rhythm

- **Space-1** `0.5rem` — masthead vertical padding, sidebar link vertical padding, table cell padding.
- **Space-2** `1rem` — gap between brand mark and sub-label, gap between action buttons, gap between the landing example h3 and code block, gap between landing entry-paths items.
- **Space-3** `1.5rem` — sidebar padding-top, gap between expressive-code blocks, top margin on `.aq-actions`, intro paragraph top margin on the landing.
- **Space-4** `2rem` — content-panel padding-block (bottom everywhere; top on mobile).
- **Section breathing room** — `2.75rem` margin-top on H2 and H3, then `1rem` to the next element.
- **Landing packet top margin** — `clamp(2.5rem, 4vw, 4rem)` above `.aq-packet`.
- **Landing roundtrip-context top margin** — `2rem`.
- **Landing landing-content side padding** — `clamp(1.125rem, 3vw, 2.75rem)` (inherits `--sl-content-pad-x`).

### Print

- On docs print, the chapter band hides, the header becomes static, and the main frame drops its top padding. The landing `@media print` block collapses `.aq-desk` to a single column and adds `break-inside: avoid` to the packet grid so the figure prints whole.

## Elevation & Depth

The custom frame is predominantly flat. Depth on surfaces we draw comes from tonal banding (Paper → White → Fog in light; Night → Night-Raised → Night-Soft in dark), hairline rules, and the contrast between the chapter band and the page below it. The native Starlight stylesheet continues to draw its own shadows where the upstream framework expects them (pagination, dialogs, etc.); the custom stylesheet does not modify those, and this document does not govern them.

The custom stylesheet declares **one** `box-shadow` rule: a small ambient lift on `.aq-actions a:hover` (`0 2px 8px rgb(0 0 0 / 0.08)`). That is the only offset blurred shadow on custom decoration. Native Starlight element shadows, where present, remain native and unchanged.

### Shadow Vocabulary

- **Action-button hover** (`box-shadow: 0 2px 8px rgb(0 0 0 / 0.08)`): applied only when the reader hovers an `.aq-actions a`. The shadow is intentionally small and ambient; it never stacks, never grows.

### Named Rules

**The Flat-by-Default Rule (custom decoration).** Surfaces drawn by the custom stylesheet are flat at rest. The chapter band, sidebar, content column, code blocks, tables, and asides carry no `box-shadow` from our styles. Custom decoration stays flat; shadows appear only as a response to pointer state on action buttons.

## Shapes

The form language is rectangular with one radius. Corners are not celebrated; they are softened just enough to keep interactive surfaces from feeling sharp.

- **Surface radius** `0.375rem` (`--aq-radius`): the chapter-band scrollbar target, action buttons, expressive-code blocks, the sidebar current-page background, the Starlight mobile-menu button, the search button, and the Starlight asides.
- **Inline-code radius** `0.2rem`: tighter than surface radius so inline `code` doesn't look like a button.
- **Chapter links** `0`: the chapter band is a typographic band, not a row of buttons. A 2px transparent border sits at the bottom of every link and turns opaque white for the current section.
- **Scrollbar** `thin`, with track colored to the local surface and thumb colored to the local rule; on the chapter band the scrollbar uses Sage on Forest.

## Components

### Brand wordmark (`aq-site-title`)

- **Shape:** no radius, no border.
- **Color:** Ink on light, Silver on dark.
- **Type:** `1.5rem`, weight 600, tracking `-0.03em`. The wordmark reads "AegisQ".
- **Sub-label** (`.aq-site-label`): rendered only when Starlight `hasSidebar` is true (documentation routes). Hidden below `64rem`; above that it becomes `inline`, sized `0.875rem`, weight 400, Moss/Sage. Home and error-page wordmarks read only "AegisQ".

### Chapter band (`aq-chapters`)

- **Shape:** full-width band, no radius, no border between band and masthead.
- **Background:** Forest (`#315e50`) in both themes — the only color the system uses identically across themes.
- **Text:** White, `0.875rem` on mobile, `0.9375rem` ≥50rem.
- **Links:** inline-flex, vertically centered, `padding: 0.5rem 0.125rem`, 2px transparent bottom border.
- **Hover:** translucent white (`rgb(255 255 255 / 0.08)`) overlay, no border change.
- **Current section:** `aria-current="location"`; bottom border turns white and weight becomes 600.
- **Focus:** outline color is White with a negative offset (`-4px`) so the ring sits inside the band.
- **Mobile:** `overflow-x: auto` so the band scrolls horizontally when the four chapter labels exceed viewport width.

### Masthead controls (native Starlight)

- **Search button** (`site-search button[data-open-modal]`): min-height `2.75rem`, radius `0.375rem`, border `var(--aq-border-strong)`. The native Pagefind modal is reused.
- **Theme select** and **language select**: `min-height: 2.75rem`. Native `<select>` controls styled to match the masthead height.
- **Mobile menu button** (`starlight-menu-button button`): positioned to sit centered against the masthead (`top: calc((var(--aq-masthead-height) - var(--sl-menu-button-size)) / 2)`), `1px` border in `--aq-border-strong`, radius `0.375rem`. The native custom element keeps its upstream shadow; the custom stylesheet sets `box-shadow: none` on the inner button to keep the masthead flat. A small inline observer mirrors `aria-expanded` from the custom element onto its inner button so assistive tech announces the menu state correctly.

### Sidebar (`sidebar-content`)

- **Padding-top:** `1.5rem`.
- **Links:** radius `0.375rem`, vertical padding `0.5rem`.
- **Current page (light):** Forest text on Selection-Light background (`#c2d9cc`), weight 600.
- **Current page (dark):** Mint text on Night-Rule background, weight 600.
- **Group labels** (`.large`): `0.875rem`, weight 600 — the sidebar section titles Starlight renders above each item group.

### Reading column (`content-panel`)

- **Padding-block:** `2rem` mobile (top and bottom). At `50rem` and up, padding-block-start becomes `2.5rem` while padding-block-end stays `2rem`.
- **Adjacent panels:** no top border, no top padding — the column reads as a continuous flow.
- **Tables:** `0.875rem` body, tabular-nums; header row uses `--aq-surface-soft` (Fog in light, Night-Soft in dark) with `--aq-text` (Ink or Silver) — the header text is not muted.
- **Asides** (`.starlight-aside`): `1px` border in `--aq-border-strong`, radius `0.375rem`, inline-start border same width as the others (no callout-style accent bar).
- **Code blocks:** the Expressive Code renderer is configured with `borderRadius: '0.375rem'` so its outer radius matches the system.

### Action buttons (`.aq-actions`)

- **Shape:** radius `0.375rem`, `1px` border, `padding: 0.625rem 1rem`.
- **Type:** `0.875rem`, weight 600, no underline.
- **Shared declaration** (`.aq-actions a`): border in `--aq-border-strong`, padding and radius as above.
- **Primary** (`.aq-actions a:first-child`): background `--aq-accent` (Forest on light, Mint on dark), border in the same color, text in `--aq-on-accent` (White on light, Night on dark).
- **Secondary** (subsequent children): transparent background, border `--aq-border-strong`, inherited link text `--aq-accent` (Forest or Mint).
- **Row:** flex, wrap, gap `1rem` row × `1.5rem` column, margin `1.5rem` top × `2rem` bottom.
- **Hover:** `box-shadow: 0 2px 8px rgb(0 0 0 / 0.08)` — the only custom `box-shadow`.
- **Focus:** `2px solid var(--aq-accent)`, offset `4px` (system focus ring, not button-local).

### Landing introduction + Open-docs CTA (`.aq-introduction`, splash only)

- **Shape:** no radius on the heading itself; CTA inherits the system radius `0.375rem`.
- **Heading:** `clamp(2.75rem, 4.2vw, 3.75rem)`, weight 600, line-height `1.04`, tracking `-0.04em`, `text-wrap: balance`. On mobile (`≤ 49.99rem`) the heading is `clamp(2.5rem, 8.5vw, 3.75rem)` and capped at `max-width: 16ch`. The h1 is split across two stacked lines (`Hybrid encryption.` and `A clear Python path.` / Spanish equivalents); the second line is a plain `span` colored `--aq-accent` and is **not italic**.
- **Intro paragraph:** `1rem`, line-height `1.7`, color `--aq-text-muted`, `margin-top: 1.5rem`. Capped at `max-width: 38ch` on desktop and `max-width: 65ch` on mobile.
- **CTA (`.aq-open-docs`):** `min-height: 2.75rem`, padding `0.625rem 1.25rem`, radius `0.375rem`, border `1px solid --aq-accent`, background `--aq-accent`, text `--aq-on-accent`. Type `0.9375rem`, weight 600, no underline. `margin-top: 1.5rem`. Hover swaps fill to `--aq-text` and text to `--aq-bg` (and border to `--aq-text`).

### Landing example + install (`.aq-example`, splash only)

- **Heading (h2):** `1rem`, weight 600, `-0.015em` tracking; line-height `1.5`. Margin `0 0 1rem`.
- **Sub-heading (h3):** `0.9375rem`, weight 500. Margin `1.5rem 0 0.75rem`. The h3 sits above the install block; the install code block carries the `Code` component (Starlight Expressive Code, configured at the project level with `borderRadius: '0.375rem'`).
- **Note (`.aq-example-note`):** `0.8125rem`, line-height `1.65`, `--aq-text-muted`. Margin-top `0.75rem`. Reads "Python 3.11 or later. ML-KEM-768 by default." (Spanish equivalent on the ES splash).

### Landing entry paths (`.aq-entry-paths`, splash only)

- **Shape:** full-height column on the right at `> 74rem`; full-width row beneath at `≤ 74rem`. Inline-start hairline (`border-inline-start: 1px solid var(--aq-border)`) plus `padding-inline-start: 1.25rem` on the right-column form; on the full-width form the hairline moves to `border-top: 1px solid var(--aq-border)`, the inline-start rule is removed, and `padding: 1.25rem 0 0` is added.
- **Heading (h2):** same as `.aq-example h2` — `1rem`, weight 600, `-0.015em` tracking.
- **List:** `list-style: none`, no padding, no margin. Items spaced `0.5rem` apart in the right-column form; in the full-width form the list becomes `display: flex; flex-wrap: wrap; gap: 0.5rem 1.75rem`.
- **Link:** inline-block, `padding-block: 0.375rem` (right-column) / `0.625rem` (full-width and mobile), color `--aq-text`, `0.9375rem`, line-height `1.5`, `text-decoration-color: --aq-border-strong`. Hover color `--aq-accent`.

### Landing Transit Packet figure (`.aq-packet`, splash only)

- **Top margin:** `clamp(2.5rem, 4vw, 4rem)`.
- **Caption (`figcaption`):** `1.125rem`, weight 500, `-0.015em` tracking.
- **Grid (`.aq-packet-parts`):** `grid-template-columns: repeat(4, minmax(0, 1fr))`, `1px` border in `--aq-border-strong`, radius `0.375rem`, `overflow: hidden`, no list markers, no padding. The four cells are equal-column by design — **the figure is excerpted, not proportional to byte size**. Cells are `1.125rem` padded, background `--aq-surface-soft` (Fog / Night-Soft), separated by an `inline-end` hairline. The first cell (ML-KEM capsule) carries `--aq-accent` background and `--aq-on-accent` text.
- **Cell label (`strong`):** `0.9375rem`, weight 600, line-height `1.5`.
- **Cell detail (`span`):** `0.8125rem`, line-height `1.5`, color `--aq-text-muted`. The first cell's `span` inherits the accent text color.
- **Order:** `[ ML-KEM capsule | AES nonce | Auth tag | Ciphertext ]`. The order is part of the canonical Transit Package format and must not be reordered.
- **Mobile (`≤ 49.99rem`):** grid becomes single-column; each cell stacks with a `border-bottom` hairline and `padding: 0.875rem 1.125rem`; the last cell drops the bottom hairline. Inline-end border is removed across the row.
- **Notes row (`.aq-packet-notes`):** flex-wrap row, `justify-content: space-between`, gap `0.5rem 1.5rem`, `margin-top: 0.75rem`, `0.8125rem`, line-height `1.6`. Caption is `--aq-text-muted`; the diagram link is `--aq-accent`.
- **Print:** `break-inside: avoid` so the figure prints whole.

### Landing roundtrip context (`.aq-roundtrip-context`, splash only)

- **Layout:** flex with `gap: var(--aq-landing-gap)` (column-gap of `clamp(1.5rem, 3vw, 2.5rem)`); at `≤ 74rem` the row collapses to `flex-direction: column` with `gap: 0.75rem`.
- **Trust paragraph:** `0.875rem`, line-height `1.75`, `max-width: 75ch`, color `--aq-text-muted`.
- **Continue link:** `--aq-accent`, `flex-shrink: 0` so it does not collapse when the paragraph is long.

### Focus, selection, and disabled state

- **Focus-visible:** `2px solid var(--aq-accent)`, `4px` offset, drawn by `:focus-visible` on every focusable element (chapter-band override uses White inside the band).
- **Selection:** `var(--aq-selection)` background (Selection-Light in light, Night-Rule in dark), text color matches the local body color.
- **Disabled buttons:** `cursor: not-allowed`, `opacity: 0.65`. No color shift.

### Reading motion (`reading-motion.ts`, `docs.css`)

| Moment | Shipped behavior |
| --- | --- |
| Home opening | Visible desk columns settle from `perspective(900px) translate3d(0, 10px, -24px) scale(0.98)`, opacity `0.82`, over `640ms`; starting delays `0/70/140ms`. Only columns already in view get this sequence. |
| Scroll continuity | Headings, code, lists, tables, asides, entry actions and the home packet/context enter once from `translateY(8px)`, opacity `0.92`, over `320ms`. Paragraphs stay still. |
| Easing | Existing `cubic-bezier(0.16, 1, 0.3, 1)`; no bounce, loops or continuous parallax. |
| Visibility | One IntersectionObserver, no scroll listeners or dependencies. Waiting content is fully visible. Targets are unobserved after entry; animation classes and transforms are removed on completion. |
| Direct reading | Hash URLs and browser-restored reading positions bypass enhancement. Keyboard focus settles its block immediately; same-page hash navigation cancels active entrances and settles all pending blocks. |
| Fallbacks | Reduced motion, absent JavaScript/IntersectionObserver and printing preserve a still, readable document. Changing to reduced motion cancels active entrances. |

Transforms affect painting only, never section order or layout. There is no blur,
persistent `will-change`, scroll hijacking, or replay on reverse scrolling.

### Not-found recovery (`NotFoundHero.astro`)

The error surface inherits the paper/forest or charcoal/mint world and the
single-tier splash masthead, including its two-row mobile controls. It uses a
`68rem` maximum width and `0.85fr / 1.15fr` columns: a large, aria-hidden 404
beside one localized H1, explanation and home/docs links. The number uses the
existing Schibsted face at `clamp(8rem, 18vw, 16rem)`; below `49.99rem` it stacks
above the message at `clamp(7rem, 30vw, 10rem)`. A hairline separates three real
documentation destinations from the message. No illustration, artificial
security claim or entrance choreography is added. The explicit EN/ES error
routes are excluded from search and indexing; native locale options point to
the static `/404.html` fallback and `/es/404/`.

## Do's and Don'ts

Concrete visual guardrails grounded in the built stylesheet. Where a guardrail is provisional or sits outside the visual system (cryptography, hosting), it is not recorded here.

### Do:

- **Do** keep the docs chapter band full-width and Forest on both themes; it is the only fully saturated surface. On splash routes the chapter band is intentionally absent (`template !== 'splash'` guard in `DocsHeader.astro`).
- **Do** cap body paragraphs and list items at `max-width: 75ch` on docs; cap landing intro paragraphs at `38ch` desktop / `65ch` mobile and the landing trust paragraph at `75ch`.
- **Do** use Forest on light and Mint on dark for primary action buttons, current docs sidebar text, and focus rings on both routes.
- **Do** pair the active docs sidebar link with Selection-Light background and Forest text (light) or Night-Rule background and Mint text (dark) — never paint a Forest block in the sidebar.
- **Do** self-host Schibsted Grotesk weights 400–700 from `website/public/fonts/` and ship the OFL notice.
- **Do** preserve the Starlight native search, theme select, language select, and mobile menu on both routes; style them, do not replace them.
- **Do** disable every animation and transition when `prefers-reduced-motion: reduce` is set.
- **Do** keep docs tables, code blocks, and asides inside the `48rem` reading column and inherit the system radius.
- **Do** restrict the reading desk to actual home paths, use the custom recovery surface for 404 entries, and retain the native Hero for other splash routes.
- **Do** widen the splash content frame to `82rem` and lay the three-column desk (`1.08fr / 1.42fr / 0.5fr`) at viewport-width strictly greater than `74rem`; switch to two columns at or below `74rem` and to a single column at or below `49.99rem`.
- **Do** keep the Transit Packet figure equal-column and accent-only-the-first-cell across all viewport widths; stack vertically on mobile.
- **Do** keep the landing h1 second line plain (non-italic) with `--aq-accent` color only; weight, tracking, and family inherit from the parent.

### Don't:

- **Don't** introduce a second reading face or a display serif. Schibsted Grotesk is the only reading family; the system monospace stack is reserved for code.
- **Don't** add raster hero imagery or marketing photography under `website/public/`. The shipping public directory currently carries only the font files and the favicon. (Documentation diagrams, photos, or inline figures that earn their place remain a future product decision and are not banned by this file.)
- **Don't** add a new `box-shadow` to custom decoration outside the action-button hover rule. Custom decoration stays flat; native Starlight element shadows are not modified.
- **Don't** recolor the docs chapter band per theme — Forest stays Forest in dark mode too on docs. The splash routes do not paint a chapter band; their saturated surface, where one appears, is the first packet cell.
- **Don't** invent brand certifications, audit claims, or performance numbers. PRODUCT.md forbids them; the design system must not contradict the product record.
- **Don't** ship heavy custom JavaScript. Custom scripts are limited to the native mobile-menu accessibility observer, shared one-shot reading-motion enhancement and error-page locale-link normalization. The two-row mobile masthead remains pure CSS.
- **Don't** duplicate the native masthead controls on the splash routes; rearrange them via CSS grid only.
- **Don't** paint a saturated hero band on the splash landing; the splash inherits paper and uses accent only on the h1 second line, the CTA fill, and the first packet cell.
- **Don't** render the packet figure proportional to byte size; the four cells are equal-column by design.
