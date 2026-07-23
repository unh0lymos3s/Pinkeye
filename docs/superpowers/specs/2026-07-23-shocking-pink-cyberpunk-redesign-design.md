# Shocking-pink cartoon redesign — design

(Filename retains "cyberpunk" from the original brief; the direction below
evolved to a cartoonish flat pink-and-white poster look — no dark mode, no
glow — per follow-up feedback.)

## Goal

Replace the current pastel hotpink/indigo/purple theme with a cartoonish,
fully-saturated shocking-pink + white look (no black, no dark mode), hide
the top nav behind a hover bubble on the right edge, and restructure the
landing page from a stacked form page into three centered controls: an
Engagement toggle, a center "The eye" button that opens the knowledge graph
on its own page, and a Launch-a-run toggle.

## 1. Palette (shocking pink field, white for contrast — no black)

The page itself is a solid shocking-pink field. Cards sit on top in a
closely-related pink shade with a thin white border and white text — low
contrast by design, for a bold "pink-on-pink" poster look. Anywhere data
actually needs to be scannable (severity, graph node type/status), white
intensity is the emphasis signal instead, since pink-on-pink can't carry
that gradation itself.

**Chrome tokens** (`web/app/globals.css` `:root`):
- `--bg`: solid shocking pink (`#ff0090`-family) — the dominant field color
- `--surface` / `--surface-2` / `--surface-3`: closely-related pink shades
  (slightly darker/more saturated than `--bg`) so cards read as distinct
  blocks without leaving the pink family
- `--border` / `--border-strong`: white at reduced/full opacity — the thin
  white borders on every card/control
- `--text`: white
- `--text-muted`: white at ~70% opacity
- `--text-dim`: white at ~45% opacity
- `--brand`: the same shocking pink as `--bg` (single flat color, no
  gradient) — used where an element needs to *say* "pink" explicitly (e.g.
  text on a white surface)
- `--ok`: white

**Primary buttons** (`.btn-primary`, "Run agent", "Create", "The eye"):
inverted — solid **white** fill with pink text/icon. This is the one
high-contrast element type in the UI, so calls-to-action visibly pop out of
the pink field instead of blending into it like the low-contrast cards do.

**Severity** (`.sev-critical` … `.sev-info`): ramped by **white**
intensity, not pink —
- critical: solid white fill, pink text (max intensity/max attention)
- high: strong white fill (~55% opacity), white text
- medium: medium white fill/outline (~35%)
- low: pale white outline (~18%)
- info: faint white outline only, muted text

The severity **word** ("critical"/"high"/...) is always printed in the
badge, so the intensity ramp is reinforcing, not the sole signal.

**Graph node types** (`GraphView.tsx` `COLORS`): solid **white** fill for
anything that needs to pop — `Service`, `Finding` — since a pink fill would
disappear into the pink canvas. Calm/structural nodes (`Engagement`, `IP`,
`Port`) are hollow: pink fill (matching the canvas) with a thin white
outline, so they recede. The exploitable ring and the "new" cross-run-status
ring both render as a pulsing white ring (thicker/brighter than the hollow
nodes' outline, so emphasis still reads). "changed" status uses a dashed
white ring at lower opacity; "gone" uses a faint, low-opacity dashed white
ring.

**Callouts** (`callout-warn`, `callout-danger`): differentiated by icon (⚠
vs ⛔) and white-fill intensity, same ramp logic as severity — danger = solid
white fill + pink text, warn = white outline + faint white fill.

**Radius tokens**: unchanged from the current theme (already rounded-corner,
solid-card style from the prior retheme) — this pass changes color, not
shape. **Shadows are removed entirely** (`--shadow`/`--shadow-sm` become
`none`) — flat cutout shapes, no drop-shadow depth; separation between cards
and the pink field comes only from the thin white border.

## 2. Nav: hover bubble, no top bar

`web/app/Nav.tsx` is rewritten from a docked top `<nav>` into a fixed,
floating control:

- Collapsed: a small circular **white** tab with the existing "◉" eye glyph
  in pink (no "Pinkeye" text), fixed to the right edge, vertically centered
  (`position: fixed; right: 0; top: 50%; translateY(-50%)`) — white so it
  actually shows up against the solid-pink page.
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
  collapsed square gets a brighter/thicker white border so it's clear which
  one is active.
- **The eye**: a larger square/rounded button, styled like the other primary
  buttons — solid **white** fill, bold pink "THE EYE" label with the eye
  glyph — centered between the two toggle boxes. It's a `Link` to `/map` —
  no form, no toggle behavior, just navigation.
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
