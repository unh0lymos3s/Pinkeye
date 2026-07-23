# Shocking-pink cyberpunk redesign — design

## Goal

Replace the current pastel hotpink/indigo/purple theme with a monochrome
shocking-pink + white + near-black cyberpunk look, hide the top nav behind a
hover bubble on the right edge, and restructure the landing page from a
stacked form page into three centered controls: an Engagement toggle, a
center "The eye" button that opens the knowledge graph on its own page, and
a Launch-a-run toggle.

## 1. Palette (fully monochrome — pink, white, black only)

No more distinct hues for brand/severity/graph. Everything is encoded with a
single shocking-pink hue at varying intensity, plus white and near-black.

**Chrome tokens** (`web/app/globals.css` `:root`):
- `--bg`: near-black (`#0a0509`)
- `--surface` / `--surface-2` / `--surface-3`: ascending near-black grays with
  a faint pink tint
- `--border` / `--border-strong`: dark pink-tinted grays
- `--text`: white/cream (`#fff6fa`)
- `--text-muted`: light pink-gray
- `--text-dim`: darker gray
- `--brand`: single solid shocking pink (`#ff0090`-family), no more
  brand/brand-2 gradient — `.btn-primary`, `.brand .eye`, focus rings, etc.
  all use the one flat color instead of `linear-gradient(brand, brand-2)`
- `--ok`: white (calm/success reads as white, not a separate green)

**Severity** (`.sev-critical` … `.sev-info`): same single pink hue, ramped by
fill intensity/weight instead of by hue —
- critical: solid pink fill, white text (max intensity)
- high: strong pink fill (~55% opacity), pink text
- medium: medium pink fill (~35%)
- low: pale pink fill (~18%)
- info: outline-only, faint pink border, muted text

The severity **word** ("critical"/"high"/...) is always printed in the
badge, so the intensity ramp is reinforcing, not the sole signal.

**Graph node types** (`GraphView.tsx` `COLORS`): white fill = calm/structural
(`Engagement`, `IP`), solid pink fill = active/notable (`Service`,
`Finding`), hollow (dark fill + pink outline) = lightweight (`Port`). The
exploitable ring and the "new" cross-run-status ring both render as a
pulsing **white** ring — max contrast against the pink fills, since white is
now reserved for "pay attention" highlights on the graph. "changed" status
uses a dashed pink ring; "gone" uses a faint dim-gray dashed ring.

**Callouts** (`callout-warn`, `callout-danger`): differentiated by icon (⚠
vs ⛔) and fill intensity (danger = solid pink + white text, warn = pink
outline + dim fill), not hue.

**Radius/shadow tokens**: unchanged from the current pastel theme (already
rounded-corner, solid-card style from the prior retheme) — this pass changes
color and structure, not shape.

## 2. Nav: hover bubble, no top bar

`web/app/Nav.tsx` is rewritten from a docked top `<nav>` into a fixed,
floating control:

- Collapsed: a small circular pink tab (the existing "◉" eye glyph, no
  "Pinkeye" text) fixed to the right edge, vertically centered
  (`position: fixed; right: 0; top: 50%; translateY(-50%)`).
- On hover (and `:focus-within` for keyboard use), it expands leftward into
  a rounded panel listing: **Home** (`/`), **Map** (`/map`), Agent Chat,
  SAST, Dashboard, Query, Guide, **API Docs** (external link, folded into
  this list instead of living outside it).
- Mouse-leave (or blur) collapses it back to the dot.
- No text ever sits permanently at the top of the viewport — the "Pinkeye"
  brand text is dropped; the dot's glyph is the only persistent brand mark,
  and it's a small edge control, not a masthead.

`web/app/layout.tsx` needs no structural change — `<Nav />` now renders as
an overlay via its own fixed positioning, so it no longer reserves layout
space above `{children}`.

## 3. Landing page (`web/app/page.tsx`)

Full rewrite. No title, no subtitle, no authorized-use banner (removed from
this page only — it still appears where it's actionable, e.g. Agent Chat).

Layout: a full-viewport-height flex row, centered both horizontally and
vertically:

```
[ Engagement box ]     [ THE EYE ]     [ Launch-a-run box ]
```

- **Toggle boxes**: collapsed state is a square, rounded-corner button
  (~160×160px) — icon + label only (`◆ ENGAGEMENT`, `▶ LAUNCH RUN`), no
  live-value preview. Clicking one toggles it open; the form (today's
  `.card-pad` content, verbatim fields/handlers, just without the "1 ·" / "2
  ·" `SectionTitle` numbering) appears in a panel **below the three-button
  row**, full width. Clicking an open box again collapses it. Both boxes can
  be open at once, stacked in that panel in click order. The row itself
  never reflows — clicking doesn't move the eye button. An open box's
  collapsed square gets a highlighted (solid pink) border so it's clear
  which one is active.
- **The eye**: a larger square/rounded button, solid pink, bold "THE EYE"
  label with the eye glyph, centered between the two toggle boxes. It's a
  `Link` to `/map` — no form, no toggle behavior, just navigation.
- State kept on this page: `useEngagement()` (selected/select/engagements),
  the create-engagement fields (`name`, `cidrs`), the launch-run fields
  (`target`, `mode`, `tool`, `intensity`), `busy`/`status`, and the two
  `expanded` booleans for the toggle boxes. `onCreate`/`onScan` handlers are
  unchanged.

## 4. New graph page (`web/app/map/page.tsx`)

Everything graph-related moves here verbatim from the old `page.tsx`:
the "full map (all engagements)" checkbox (was top-right of the old
page-head), the node/status legend, `<GraphView>` with its fullscreen
support, the empty-state copy, and the `ChangesPanel` ("Changes since last
run"). This page keeps a normal content heading ("Knowledge Graph") — the
no-title rule was about the site masthead, not page content.

It calls `useEngagement()` independently (same per-page pattern the app
already uses elsewhere) to know which engagement's graph/changes to poll.

## 5. Sharing `lastRunId` across pages

Today `lastRunId` is local `useState` in `page.tsx`, feeding the Changes
panel that lived on the same page. Now the run is launched on `/` but the
Changes panel lives on `/map`, so it needs to survive navigation.

New `web/lib/useLastRun.ts`, mirroring the existing `useEngagement`
localStorage pattern: keyed as `eye.lastRunId.<engagementId>` so each
engagement remembers its own most recent run. `page.tsx` calls `setLastRunId`
after a successful `createRun`; `map/page.tsx` reads it for the selected
engagement to drive the Changes panel poll.

## Out of scope

- No glow/scanline/glitch effects (explicitly declined).
- No changes to the SAST, Dashboard, Query, Guide, or Agent Chat page
  layouts beyond the automatic palette recolor (they consume the same CSS
  tokens/components) and the nav no longer being a docked bar above them.
- No backend/API changes.
