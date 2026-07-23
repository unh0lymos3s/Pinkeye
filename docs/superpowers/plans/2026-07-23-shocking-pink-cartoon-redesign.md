# Shocking-Pink Cartoon Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retheme the Pinkeye Next.js frontend to a flat shocking-pink + white cartoon palette (no dark mode, no shadows), replace the docked top nav with a hover bubble on the right edge, split the landing page into two collapsible toggle boxes plus a center "The eye" button, and move the knowledge graph to its own `/map` route.

**Architecture:** Pure frontend change inside `web/`. Colors are almost entirely CSS custom properties in `web/app/globals.css`, consumed by class names across every page — one token rewrite recolors most of the app. The two exceptions are SVG fill/stroke attributes in `web/app/GraphView.tsx` (can't read CSS vars) and the JSX/route structure for the nav and landing page, which get rewritten. No backend/API changes.

**Tech Stack:** Next.js 14 (app router), React 18, TypeScript. No test framework is configured in this project (`web/package.json` has no Jest/Vitest/RTL). Verification per task is therefore: (1) `tsc --noEmit` compiles clean, (2) `grep` the edited source file for the literal strings that must be present/absent, (3) a `curl` smoke check against the running dev server confirming the affected route still serves and contains the expected markers. Task 7 adds an optional best-effort Playwright screenshot sweep on top of that.

## Global Constraints

- Palette is exactly two colors plus opacity ramps of white — no black, no gradients, no glow/scanline/glitch effects, no drop-shadows (`--shadow`/`--shadow-sm` tokens and every consumer of them are removed).
- The canonical shocking pink value is `#ff2da0`. It must appear identically in `web/app/globals.css` (`--bg`, `--brand`) and as the exported `PINK` constant in `web/app/GraphView.tsx` — these are the only two places the pink hex is allowed to be hand-typed. White is always `#ffffff` or an `rgba(255, 255, 255, <alpha>)` of it.
- Primary buttons (`.btn-primary`, the eye button) are inverted: solid white fill, pink text/icon — the one high-contrast element type, everything else is pink-on-pink with thin white borders.
- Severity badges, callouts, and graph node/status emphasis are encoded by **white intensity** (opacity ramp), never by a second hue, since pink-on-pink can't self-contrast.
- The landing page (`/`) has no title, no subtitle, no "Authorized use only" banner. It is exactly: an Engagement toggle box (left), "The eye" button (center, links to `/map`), a Launch-a-run toggle box (right), vertically and horizontally centered, plus a below-the-row panel for whichever toggle box(es) are open.
- The nav is never a docked top bar. It's `position: fixed`, a small white circular tab on the right edge vertically centered, expanding into a link panel on hover/`:focus-within`. No "Pinkeye" brand text anywhere in the UI.
- Pages other than `/`, `/map`, `Nav.tsx`, and `globals.css` (i.e. `dashboard`, `query`, `guide`, `sast`, `agent`) get the palette change automatically through shared CSS classes/tokens and are not otherwise restructured.
- Spec reference: `docs/superpowers/specs/2026-07-23-shocking-pink-cyberpunk-redesign-design.md`.

---

## Task 1: Palette tokens + generic component restyle (`globals.css`)

**Files:**
- Modify: `web/app/globals.css` (complete rewrite of the file's contents — every rule)

**Interfaces:**
- Produces: the CSS custom properties every later task and every unmodified page (`dashboard`, `query`, `guide`, `sast`, `agent`) consumes: `--bg`, `--surface`, `--surface-2`, `--surface-3`, `--border`, `--border-strong`, `--text`, `--text-muted`, `--text-dim`, `--brand`, `--brand-soft`, `--brand-ring`, `--critical`, `--high`, `--medium`, `--low`, `--info`, `--ok`, `--warn`, `--radius`, `--radius-sm`, `--radius-lg`, `--font`, `--mono`. (`--brand-2`, `--shadow`, `--shadow-sm`, and the `--node-*` tokens are removed — nothing after this task may reference them.)

- [ ] **Step 1: Confirm frontend deps are installed**

Run: `cd /home/samosa/Pinkeye/web && [ -d node_modules ] || npm install`
Expected: exits 0 either way (no-op if already present).

- [ ] **Step 2: Record the pre-change baseline typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0` (project currently typechecks clean). If it doesn't, stop and investigate before proceeding — this task must not be the thing blamed for pre-existing breakage.

- [ ] **Step 3: Rewrite `web/app/globals.css`**

Replace the entire file with:

```css
/* Pinkeye — design system.
   One place for tokens (color, spacing, type, radius) and the shared component
   classes the pages compose. Pages should reach for these classes before inline styles.
   Palette: flat shocking pink + white only — no black, no gradients, no shadows. */

:root {
  /* Surfaces — solid shocking pink field, closely-related shades for layering */
  --bg: #ff2da0;
  --surface: #ff3ea6;
  --surface-2: #ff50ad;
  --surface-3: #ff62b4;
  --border: rgba(255, 255, 255, 0.5);
  --border-strong: rgba(255, 255, 255, 0.85);

  /* Text — white only, opacity ramp for hierarchy */
  --text: #ffffff;
  --text-muted: rgba(255, 255, 255, 0.72);
  --text-dim: rgba(255, 255, 255, 0.45);

  /* Brand — single flat shocking pink, no gradient */
  --brand: #ff2da0;
  --brand-soft: rgba(255, 255, 255, 0.16);
  --brand-ring: rgba(255, 255, 255, 0.7);

  /* Severity / status — white-intensity ramp (pink can't self-contrast on a pink field) */
  --critical: #ffffff;
  --high: rgba(255, 255, 255, 0.72);
  --medium: rgba(255, 255, 255, 0.48);
  --low: rgba(255, 255, 255, 0.28);
  --info: rgba(255, 255, 255, 0.14);
  --ok: #ffffff;
  --warn: #ffffff;

  --radius: 16px;
  --radius-sm: 12px;
  --radius-lg: 24px;

  /* Monospaced everywhere for the terminal aesthetic. */
  --font: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  --mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
}

* { box-sizing: border-box; }

html, body { padding: 0; margin: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
  font-size: 14px;
  line-height: 1.55;
}

a { color: inherit; }

/* Mono fonts render wider, so tighten headings less than a proportional face would. */
h1, h2, h3, h4 { margin: 0; font-weight: 700; letter-spacing: -0.005em; }
h1 { font-size: 23px; }
h2 { font-size: 17px; }
h3 { font-size: 15px; }

input, select, textarea, button { accent-color: var(--brand); }

::selection { background: rgba(255, 255, 255, 0.35); color: var(--brand); }

* { scrollbar-width: thin; scrollbar-color: rgba(255, 255, 255, 0.5) transparent; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.5); border-radius: 999px; border: 2px solid transparent; background-clip: padding-box; }
::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.8); background-clip: padding-box; }

/* ---- Layout ---- */
.page { max-width: 1160px; margin: 0 auto; padding: 28px 24px 72px; }
.page-head {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 16px; flex-wrap: wrap; margin-bottom: 6px;
}
.page-sub { color: var(--text-muted); margin: 4px 0 0; max-width: 68ch; }
.row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.stack { display: flex; flex-direction: column; }
.spacer { flex: 1; }
.section-title { display: flex; align-items: center; gap: 10px; margin: 30px 0 12px; }
.section-title h3 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); }
.section-title .rule { flex: 1; height: 1px; background: var(--border); }

/* ---- Nav (docked bar — replaced by .nav-bubble in Task 3) ---- */
.nav {
  position: sticky; top: 0; z-index: 20;
  display: flex; align-items: center; gap: 4px;
  padding: 10px 20px;
  background: rgba(255, 45, 160, 0.9);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border);
}
.brand { display: flex; align-items: center; gap: 9px; font-weight: 750; margin-right: 14px; }
.brand .eye {
  width: 24px; height: 24px; border-radius: 9px; display: grid; place-items: center;
  background: #ffffff;
  color: var(--brand); font-size: 13px;
}
.brand .name { font-size: 14.5px; letter-spacing: -0.01em; }
.nav-link {
  padding: 7px 12px; border-radius: 8px; text-decoration: none;
  color: var(--text-muted); font-weight: 500; transition: background 0.12s, color 0.12s;
}
.nav-link:hover { color: var(--text); background: var(--surface-2); }
.nav-link.active { color: var(--text); background: var(--brand-soft); box-shadow: inset 0 0 0 1px var(--brand-ring); }

/* ---- Cards ---- */
.card {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
}
.card-pad { padding: 18px; }

.kpi {
  position: relative; overflow: hidden;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 16px 18px 16px 22px; min-width: 158px; flex: 1;
}
.kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 5px; border-radius: 0 4px 4px 0; background: var(--accent, #ffffff); opacity: 0.9; }
.kpi .label { font-size: 11.5px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.07em; }
.kpi .value { font-size: 30px; font-weight: 720; margin-top: 6px; color: var(--text); letter-spacing: -0.02em; }
.kpi .hint { font-size: 12px; color: var(--text-dim); margin-top: 2px; }

/* ---- Controls ---- */
.input, .select, .textarea {
  padding: 9px 11px; border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong); background: var(--surface);
  color: var(--text); font: inherit; font-size: 13.5px; outline: none;
  transition: border-color 0.12s, box-shadow 0.12s;
}
.input::placeholder, .textarea::placeholder { color: var(--text-dim); }
.input:focus, .select:focus, .textarea:focus { border-color: #ffffff; box-shadow: 0 0 0 3px var(--brand-soft); }
.textarea { width: 100%; min-height: 76px; font-family: var(--mono); font-size: 12.5px; resize: vertical; }
.field { display: flex; flex-direction: column; gap: 5px; }
.field > label { font-size: 12px; color: var(--text-muted); font-weight: 500; }

.btn {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 9px 14px; border-radius: var(--radius-sm); cursor: pointer;
  border: 1px solid var(--border-strong); background: var(--surface-3); color: var(--text);
  font: inherit; font-size: 13.5px; font-weight: 550; white-space: nowrap;
  transition: background 0.12s, border-color 0.12s, opacity 0.12s, transform 0.05s;
}
.btn:hover { background: var(--surface-3); border-color: var(--border-strong); filter: brightness(1.15); }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: 0.45; cursor: not-allowed; }
.btn-primary {
  background: #ffffff;
  border-color: transparent; color: var(--brand); font-weight: 650;
}
.btn-primary:hover { background: #ffeaf5; }
.btn-ghost { background: transparent; }

/* ---- Badges ---- */
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600;
  text-transform: capitalize; line-height: 1.7;
  border: 1px solid transparent;
}
.badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev-critical { color: var(--brand); background: #ffffff; border-color: #ffffff; }
.sev-high     { color: var(--text); background: rgba(255, 255, 255, 0.55); border-color: rgba(255, 255, 255, 0.7); }
.sev-medium   { color: var(--text); background: rgba(255, 255, 255, 0.32); border-color: rgba(255, 255, 255, 0.5); }
.sev-low      { color: var(--text); background: rgba(255, 255, 255, 0.16); border-color: rgba(255, 255, 255, 0.35); }
.sev-info     { color: var(--text-muted); background: transparent; border-color: rgba(255, 255, 255, 0.25); }
.pill { color: var(--text-muted); background: var(--surface-3); border-color: var(--border); }

/* ---- Tables ---- */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
table.data { width: 100%; border-collapse: collapse; font-size: 13px; }
table.data thead th {
  text-align: left; padding: 11px 14px; color: var(--text-muted);
  font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
  background: var(--surface-2); border-bottom: 1px solid var(--border); white-space: nowrap;
}
table.data tbody td { padding: 11px 14px; border-top: 1px solid var(--border); vertical-align: middle; }
table.data tbody tr:hover { background: var(--surface-2); }
table.data td.mono, table.data td .mono { font-family: var(--mono); font-size: 12px; color: var(--text-muted); }
.empty { padding: 26px; text-align: center; color: var(--text-dim); }

/* ---- Callout ---- */
.callout {
  display: flex; gap: 11px; padding: 13px 15px; border-radius: var(--radius);
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text-muted);
}
.callout .ico { flex: none; font-size: 15px; line-height: 1.5; }
.callout strong { color: var(--text); font-weight: 600; }
.callout-warn { border-color: rgba(255, 255, 255, 0.55); background: rgba(255, 255, 255, 0.12); }
.callout-warn .ico { color: var(--text); }
.callout-danger { border-color: #ffffff; background: rgba(255, 255, 255, 0.22); }
.callout-danger .ico { color: var(--brand); }

/* ---- Misc ---- */
.muted { color: var(--text-muted); }
.dim { color: var(--text-dim); }
.mono { font-family: var(--mono); }
.tag {
  display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11.5px;
  font-family: var(--mono); background: var(--surface-3); color: var(--text-muted); border: 1px solid var(--border);
}
/* Change tags for the "Changes since last run" panel; intensity mirrors the graph status rings. */
.change-tag {
  display: inline-block; min-width: 96px; text-align: center; padding: 2px 8px; border-radius: 6px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.02em; text-transform: uppercase;
  border: 1px solid var(--border); color: var(--text);
}
.change-new { border-color: #ffffff; background: rgba(255, 255, 255, 0.24); color: var(--text); }
.change-changed { border-color: rgba(255, 255, 255, 0.65); background: rgba(255, 255, 255, 0.14); color: var(--text); }
.change-gone { border-color: rgba(255, 255, 255, 0.35); background: rgba(255, 255, 255, 0.08); color: var(--text-dim); }
.change-danger { border-color: var(--brand); background: #ffffff; color: var(--brand); }
.legend { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.legend .item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-muted); }
.legend .swatch { width: 9px; height: 9px; border-radius: 50%; }
code.k { font-family: var(--mono); background: var(--surface-3); padding: 1px 6px; border-radius: 5px; font-size: 12.5px; color: var(--text); border: 1px solid var(--border); }

/* Status dot for run/live state */
.live { display: inline-flex; align-items: center; gap: 7px; color: var(--text-muted); font-size: 13px; }
.live .beat { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 0 0 rgba(255,255,255,0.5); animation: beat 1.8s infinite; }
@keyframes beat { 0% { box-shadow: 0 0 0 0 rgba(255,255,255,0.45); } 70% { box-shadow: 0 0 0 6px rgba(255,255,255,0); } 100% { box-shadow: 0 0 0 0 rgba(255,255,255,0); } }

/* ---- Agent chat: pipeline rail, progress, activity, transcript ---- */
.pipeline { display: flex; flex-wrap: wrap; gap: 8px; }
.pipeline .stage {
  display: inline-flex; align-items: center; gap: 7px; padding: 6px 12px; border-radius: 999px;
  font-size: 12.5px; color: var(--text-dim); background: var(--surface-2);
  border: 1px solid var(--border); text-transform: capitalize; transition: all 0.2s ease;
}
.pipeline .stage .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-dim); }
.pipeline .stage.done { color: var(--text-muted); }
.pipeline .stage.done .dot { background: var(--ok); }
.pipeline .stage.active {
  color: var(--text); background: var(--brand-soft); border-color: var(--brand-ring);
  box-shadow: 0 0 0 3px var(--brand-soft);
}
.pipeline .stage.active .dot { background: #ffffff; animation: beat 1.6s infinite; }
.pipeline .stage.gated { opacity: 0.45; }
.pipeline .stage.gated .dot { background: var(--border-strong); }

.progress-wrap { margin-top: 16px; }
.progress-label { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
.progress-track { height: 8px; border-radius: 999px; background: var(--surface-3); overflow: hidden; border: 1px solid var(--border); }
.progress-fill { height: 100%; border-radius: 999px; background: #ffffff; transition: width 0.4s ease; }

.activity { display: inline-flex; align-items: center; gap: 8px; margin-top: 14px; font-size: 13px; color: var(--text-muted); font-family: var(--mono); }
.activity .pulse { width: 8px; height: 8px; border-radius: 50%; background: #ffffff; box-shadow: 0 0 0 0 var(--brand-ring); animation: beat 1.4s infinite; }

.chat { display: flex; flex-direction: column; gap: 10px; padding: 16px; max-height: 560px; overflow-y: auto; }
.chat .msg { padding: 10px 13px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--surface-2); font-size: 13.5px; line-height: 1.5; }
.chat .msg .who { display: block; font-size: 11.5px; color: var(--text-muted); margin-bottom: 4px; font-weight: 600; }
.chat .msg .body { color: var(--text); white-space: pre-wrap; }
.chat .msg.reason { background: var(--surface); border-left: 2px solid #ffffff; }
.chat .msg.tool { background: var(--surface-3); }
.chat .msg.tool .who { color: var(--ok); }
.chat .msg.tool.denied { border-color: #ffffff; background: rgba(255,255,255,0.14); }
.chat .msg.tool.denied .who { color: #ffffff; }
.chat .msg.tool .err { color: #ffffff; }
.chat .msg.sys { background: transparent; border: none; padding: 3px 4px; color: var(--text-muted); font-size: 12.5px; font-family: var(--mono); }
.chat .msg.sys b { color: var(--text); }
.chat .msg.sys .tag { margin-right: 8px; text-transform: capitalize; }
.chat .msg.done-line { text-align: center; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; font-size: 11px; padding: 8px 0; }
.chat .msg.finding { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; background: var(--surface-3); }
.chat .msg.finding .title { color: var(--text); font-weight: 500; }
.chat .msg.change { background: rgba(255, 255, 255, 0.12); border-color: #ffffff; }
.chat .msg.change .who { color: #ffffff; }
.chat .msg.sys.refusal { border: 1px solid rgba(255,255,255,0.5); background: rgba(255,255,255,0.1); padding: 8px 11px; border-radius: var(--radius-sm); font-family: inherit; }
.chat .msg.sys.refusal .who { color: #ffffff; }

/* ---- Knowledge-graph fullscreen ---- */
.mini-btn {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text-muted);
  cursor: pointer;
  font: inherit;
  font-size: 12px;
  line-height: 1;
  padding: 4px 9px;
  margin-left: 10px;
  border-radius: var(--radius-sm);
  transition: border-color 0.12s, color 0.12s, background 0.12s;
}
.mini-btn:hover { border-color: var(--border-strong); color: var(--text); background: var(--surface-2, var(--surface)); }

.graph-card { transition: none; }
.graph-fullscreen {
  position: fixed;
  inset: 0;
  z-index: 1000;
  margin: 0;
  border-radius: 0;
  display: flex;
  flex-direction: column;
  padding: 14px 16px 16px !important;
  background: var(--bg);
}
/* In fullscreen, the graph area grows to fill the remaining height. */
.graph-fullscreen > svg { flex: 1; min-height: 0; }
.graph-fs-exit { align-self: flex-end; margin: 0 0 8px 0; }

/* ---- Pipeline: operator-skipped stage (tools deselected in the tool library) ---- */
/* Distinct from .gated (scope-denied): dashed outline + strike so it reads as "switched off". */
.pipeline .stage.skipped {
  opacity: 0.4;
  border-style: dashed;
  color: var(--text-dim);
  text-decoration: line-through;
  text-decoration-color: var(--border-strong);
}
.pipeline .stage.skipped .dot { background: var(--border-strong); }

/* ---- Tool library dropdown (agent-mode tool selection) ---- */
.tool-lib { position: relative; }
.tool-lib-trigger {
  display: inline-flex; align-items: center; justify-content: space-between; gap: 10px;
  width: 100%; min-width: 170px;
  padding: 9px 11px; border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong); background: var(--surface);
  color: var(--text); font: inherit; font-size: 13.5px; cursor: pointer;
  transition: border-color 0.12s, box-shadow 0.12s;
}
.tool-lib-trigger:hover { border-color: var(--brand-ring); }
.tool-lib-trigger:focus-visible { outline: none; border-color: #ffffff; box-shadow: 0 0 0 3px var(--brand-soft); }
.tool-lib-trigger:disabled { opacity: 0.55; cursor: default; }
.tool-lib-trigger[aria-expanded="true"] { border-color: #ffffff; box-shadow: 0 0 0 3px var(--brand-soft); }

.tool-menu {
  position: absolute; z-index: 40; top: calc(100% + 6px); left: 0;
  width: 300px; max-width: 84vw;
  background: var(--surface-2); border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  overflow: hidden;
}
.tool-menu-head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 11.5px;
  text-transform: uppercase; letter-spacing: 0.06em;
}
.tool-menu-body { max-height: 340px; overflow-y: auto; padding: 6px; }
.tool-group + .tool-group { margin-top: 6px; }
.tool-group-title {
  padding: 6px 8px 4px; font-size: 11px; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.07em;
}
.tool-row {
  display: flex; align-items: center; gap: 9px; padding: 6px 8px; border-radius: var(--radius-sm);
  cursor: pointer; font-size: 13px;
}
.tool-row:hover { background: var(--surface-3); }
.tool-row input { flex: none; }
.tool-name { color: var(--text); }
.tool-flag { color: #ffffff; border-color: rgba(255, 255, 255, 0.5); }
.tool-menu-foot { padding: 8px 12px; border-top: 1px solid var(--border); font-size: 12px; }

/* Plan bubble: the run's opening pipeline announcement, shown inline in the transcript. */
.chat .msg.sys.plan-msg { font-family: inherit; color: var(--text-muted); }
.chat .msg.sys.plan-msg .who { color: #ffffff; font-family: var(--mono); }

/* Uncapped transcript: show the entire run as one flowing chat (page scrolls instead of an inner box). */
.chat.chat-full { max-height: none; }

/* ---- Interactive chat: the agent's questions and the operator's replies ---- */
.chat .msg.ask {
  border-color: #ffffff;
  background: rgba(255, 255, 255, 0.1);
  border-left: 3px solid #ffffff;
}
.chat .msg.ask .who { color: #ffffff; }
.chat .msg.ask.ask-permission {
  border-color: rgba(255, 255, 255, 0.6);
  background: rgba(255, 255, 255, 0.06);
  border-left-color: rgba(255, 255, 255, 0.6);
}
.chat .msg.ask.ask-permission .who { color: var(--text-muted); }
.ask-action { margin-top: 6px; font-size: 12.5px; color: var(--text-muted); }

/* Operator replies read as the "other side" of the conversation: aligned right, white-tinted. */
.chat .msg.user-reply {
  align-self: flex-end; max-width: 80%;
  background: rgba(255, 255, 255, 0.14); border-color: #ffffff;
}
.chat .msg.user-reply .who { color: #ffffff; text-align: right; }
.chat .msg.user-reply.auto { align-self: stretch; background: var(--surface-2); border-style: dashed; }
.chat .msg.user-reply.auto .who { color: var(--text-dim); text-align: left; }

/* Specialist sub-agents: a delegated pass reads as one indented group between its start/end headers.
   The header rows sit at the orchestrator's level; the child's activity nests under a white rail. */
.chat .msg.subagent-start .who,
.chat .msg.subagent-end .who { color: #ffffff; text-transform: capitalize; }
.chat .nested-sub {
  margin-left: 14px; padding-left: 12px;
  border-left: 2px solid var(--border-strong);
}

/* Composer: the reply box under the transcript. Dim until the agent asks, then it lights up. */
.composer {
  margin-top: 10px; padding: 12px 14px; border-radius: var(--radius);
  border: 1px solid var(--border); background: var(--surface);
  transition: border-color 0.15s, box-shadow 0.15s;
}
.composer.active { border-color: #ffffff; box-shadow: 0 0 0 3px var(--brand-soft); }
.composer-head {
  display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
  font-size: 12.5px; color: #ffffff; font-family: var(--mono);
}
.composer-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

/* SAST tab: codebase drop zone + analyzer toggles. */
.sast-drop {
  display: flex; align-items: center; gap: 16px; justify-content: center; text-align: center;
  padding: 26px 20px; border-radius: var(--radius); cursor: pointer;
  border: 1.5px dashed var(--border-strong); background: var(--surface-2);
  color: var(--text-muted); transition: border-color 0.15s, background 0.15s, color 0.15s;
}
.sast-drop:hover { border-color: #ffffff; color: var(--text); }
.sast-drop.over { border-color: #ffffff; background: rgba(255,255,255,0.14); color: var(--text); }
.sast-drop-icon { font-size: 30px; color: #ffffff; line-height: 1; }
.sast-drop .mono { color: var(--text); font-size: 14px; }

.sast-engine {
  display: flex; align-items: center; gap: 9px; padding: 10px 13px; cursor: pointer;
  border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--surface-2);
  transition: border-color 0.12s, background 0.12s; min-width: 240px;
}
.sast-engine:hover { border-color: var(--border-strong); }
.sast-engine.on { border-color: #ffffff; background: rgba(255,255,255,0.14); }
.sast-engine.missing { opacity: 0.5; cursor: not-allowed; }
.sast-engine-name { font-weight: 600; color: var(--text); }
.sast-engine-hint { font-size: 11.5px; }
```

- [ ] **Step 4: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0` (CSS-only change, TypeScript is unaffected — this just confirms nothing else broke).

- [ ] **Step 5: Grep the file for required tokens and forbidden leftovers**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c -- '--bg: #ff2da0;' app/globals.css
grep -c -- '--brand: #ff2da0;' app/globals.css
grep -c -- '--text: #ffffff;' app/globals.css
grep -c -- '--shadow' app/globals.css
grep -c -- '#1c1330\|#251a3f\|#2d2049\|#382957\|#fbf3ec\|#cbb9e3\|#9683b8' app/globals.css
```
Expected: first three commands each print `1`; last two print `0` (no leftover dark-theme tokens, no shadow references).

- [ ] **Step 6: Smoke-test the running app**

Run:
```bash
cd /home/samosa/Pinkeye/web
curl -sf http://localhost:3000/dashboard >/dev/null 2>&1 || { nohup npm run dev > /tmp/pinkeye-dev.log 2>&1 & disown; }
timeout 40 bash -c 'until curl -sf http://localhost:3000/dashboard >/dev/null; do sleep 1; done'
curl -s http://localhost:3000/dashboard | grep -c 'Failed to compile\|Unhandled Runtime Error'
```
Expected: the last command prints `0` (dev server compiles the app with the new stylesheet; leave the dev server running in the background for later tasks).

- [ ] **Step 7: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/app/globals.css
git commit -m "$(cat <<'EOF'
Retheme frontend tokens to flat shocking-pink + white

Replaces the pastel indigo/purple palette with a solid shocking-pink
field, white for all borders/text/contrast, and a white-intensity ramp
for severity/status instead of a second hue. Drops the brand gradient
and every box-shadow per the cartoon-poster direction.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Graph node/status colors (`GraphView.tsx`)

**Files:**
- Modify: `web/app/GraphView.tsx` (full rewrite)

**Interfaces:**
- Consumes: `Graph` type from `../lib/api` (unchanged).
- Produces: `export const PINK = "#ff2da0"` and `export const WHITE = "#ffffff"` — Task 5's map page imports both for its legend swatches. Default export `GraphView({ graph, fill })` signature is unchanged, so no caller needs updating beyond what Task 1 already covers via CSS.

- [ ] **Step 1: Rewrite `web/app/GraphView.tsx`**

Replace the entire file with:

```tsx
"use client";
// Self-contained SVG knowledge-graph view. Runs a tiny force simulation client-side so we don't
// pull in an external graph library. Colors nodes by their Neo4j label. Renders responsively via
// a fixed simulation coordinate space projected through an SVG viewBox.
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Graph } from "../lib/api";

// Single source of truth for the two-color palette (SVG fill/stroke attributes can't read CSS
// vars). Kept in sync with --bg/--brand and --text in globals.css.
export const PINK = "#ff2da0";
export const WHITE = "#ffffff";

// Node fill/stroke by Neo4j label. "Pop" types (Service, Finding) render solid white so they read
// as the notable/active layer; "calm" structural types (Engagement, IP, Port) render hollow — pink
// fill matching the canvas, thin white outline — so they recede into the field.
const COLORS: Record<string, { fill: string; stroke: string }> = {
  Engagement: { fill: PINK, stroke: WHITE },
  IP: { fill: PINK, stroke: WHITE },
  Port: { fill: PINK, stroke: WHITE },
  Service: { fill: WHITE, stroke: PINK },
  Finding: { fill: WHITE, stroke: PINK },
  Node: { fill: PINK, stroke: WHITE },
};

const W = 960;
const H = 560;

type P = {
  id: string;
  label: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  title: string;
  exploitable: boolean; // Service/Endpoint proven exploitable, or a target device
  status: string; // cross-run memory status: new | changed | active | gone
};

// Ring color for a node's cross-run memory status; null = no status ring. All white, ramped by
// opacity so "new" (max attention) reads brightest and "gone" (least) fades toward the canvas.
const STATUS_COLOR: Record<string, string> = {
  new: "rgba(255, 255, 255, 0.95)",
  changed: "rgba(255, 255, 255, 0.55)",
  gone: "rgba(255, 255, 255, 0.3)",
};

// Label a node by the field that actually identifies its type, so the IP -> Port -> Service chain
// reads as e.g. "10.0.0.5" -> ":22/tcp" -> "ssh" instead of the IP repeated at every level. Every
// node carries `address` (the parent IP) for MERGE keying, so a type-blind lookup showed the IP
// everywhere — here the node's Neo4j label decides which property is its name.
function nodeTitle(label: string, props: Record<string, unknown>): string {
  const s = (v: unknown) => (v == null ? "" : String(v));
  switch (label) {
    case "Engagement":
      return s(props.name) || "engagement";
    case "IP":
      return s(props.address) || s(props.hostname) || "ip";
    case "Port": {
      const num = props.number ?? props.port;
      const proto = s(props.proto);
      return num != null ? `:${num}${proto ? `/${proto}` : ""}` : "port";
    }
    case "Service":
      return (
        s(props.name) ||
        s(props.product) ||
        (props.port != null ? `:${props.port}` : "") ||
        "service"
      );
    case "Endpoint":
      return s(props.url) || s(props.address) || "endpoint";
    case "Finding":
      return s(props.title) || s(props.category) || "finding";
    case "AttackChain":
      return s(props.title) || "chain";
    default:
      return s(props.address) || s(props.name) || s(props.title) || "node";
  }
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

export default function GraphView({ graph, fill = false }: { graph: Graph; fill?: boolean }) {
  const [nodes, setNodes] = useState<P[]>([]);
  const [hover, setHover] = useState<string | null>(null);
  const raf = useRef<number>();

  // Pan/zoom navigation: the viewBox is the "camera". Dragging pans it; the wheel zooms toward the
  // cursor; double-click resets. Node positions come from the simulation and are unaffected.
  const [view, setView] = useState({ x: 0, y: 0, w: W, h: H });
  const [panning, setPanning] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ sx: number; sy: number; vx: number; vy: number } | null>(null);
  const resetView = () => setView({ x: 0, y: 0, w: W, h: H });

  const onDown = (e: ReactMouseEvent) => {
    drag.current = { sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y };
    setPanning(true);
  };
  const onMove = (e: ReactMouseEvent) => {
    const d = drag.current;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!d || !rect) return;
    setView((v) => ({
      ...v,
      x: d.vx - (e.clientX - d.sx) * (v.w / rect.width),
      y: d.vy - (e.clientY - d.sy) * (v.h / rect.height),
    }));
  };
  const endPan = () => {
    drag.current = null;
    setPanning(false);
  };

  // Wheel zoom needs a non-passive native listener so preventDefault stops the page from scrolling.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const factor = e.deltaY < 0 ? 0.85 : 1.0 / 0.85; // in / out
      setView((v) => {
        const nw = clamp(v.w * factor, W * 0.2, W * 3);
        const nh = nw * (H / W); // keep the coordinate-space aspect so nodes don't distort
        const fx = (e.clientX - rect.left) / rect.width;
        const fy = (e.clientY - rect.top) / rect.height;
        return { x: v.x + fx * v.w - fx * nw, y: v.y + fy * v.h - fy * nh, w: nw, h: nh };
      });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  // Seed node positions whenever the graph identity set changes.
  const seed = useMemo(() => graph.nodes.map((n) => n.id).join(","), [graph]);
  useEffect(() => {
    setNodes(
      graph.nodes.map((n, i) => ({
        id: n.id,
        label: n.label,
        title: nodeTitle(n.label, n.props),
        exploitable: Boolean(n.props.exploitable || n.props.is_target),
        status: (n.props.status as string) || "",
        x: W / 2 + Math.cos((i / Math.max(1, graph.nodes.length)) * 2 * Math.PI) * 180,
        y: H / 2 + Math.sin((i / Math.max(1, graph.nodes.length)) * 2 * Math.PI) * 180,
        vx: 0,
        vy: 0,
      }))
    );
  }, [seed]); // eslint-disable-line react-hooks/exhaustive-deps

  // Force simulation: repulsion between all nodes, spring pull along edges, gentle centering.
  useEffect(() => {
    if (nodes.length === 0) return;
    const step = () => {
      setNodes((prev) => {
        const next = prev.map((n) => ({ ...n }));
        const idx = new Map(next.map((n, i) => [n.id, i]));
        for (let i = 0; i < next.length; i++) {
          for (let j = i + 1; j < next.length; j++) {
            const a = next[i], b = next[j];
            let dx = a.x - b.x, dy = a.y - b.y;
            let d2 = dx * dx + dy * dy || 0.01;
            const f = 4000 / d2;
            const d = Math.sqrt(d2);
            a.vx += (dx / d) * f; a.vy += (dy / d) * f;
            b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
          }
        }
        for (const e of graph.edges) {
          const a = next[idx.get(e.source) ?? -1], b = next[idx.get(e.target) ?? -1];
          if (!a || !b) continue;
          const dx = b.x - a.x, dy = b.y - a.y;
          const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
          const f = (d - 90) * 0.02;
          a.vx += (dx / d) * f; a.vy += (dy / d) * f;
          b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
        }
        for (const n of next) {
          n.vx += (W / 2 - n.x) * 0.002;
          n.vy += (H / 2 - n.y) * 0.002;
          n.vx *= 0.85; n.vy *= 0.85;
          n.x += n.vx; n.y += n.vy;
        }
        return next;
      });
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [seed, graph.edges]); // eslint-disable-line react-hooks/exhaustive-deps

  const pos = new Map(nodes.map((n) => [n.id, n]));

  return (
    <svg
      ref={svgRef}
      viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
      width="100%"
      // In fullscreen the container drives the size (svg fills it, viewBox keeps it centered);
      // otherwise the fixed aspect ratio keeps the inline card a sensible height.
      height={fill ? "100%" : undefined}
      preserveAspectRatio="xMidYMid meet"
      onMouseDown={onDown}
      onMouseMove={onMove}
      onMouseUp={endPan}
      onMouseLeave={endPan}
      onDoubleClick={resetView}
      style={{
        display: "block",
        background: PINK,
        borderRadius: 8,
        cursor: panning ? "grabbing" : "grab",
        touchAction: "none",
        ...(fill ? { flex: 1, minHeight: 0, height: "100%" } : { aspectRatio: `${W} / ${H}` }),
      }}
    >
      {graph.edges.map((e, i) => {
        const a = pos.get(e.source), b = pos.get(e.target);
        if (!a || !b) return null;
        const active = hover && (e.source === hover || e.target === hover);
        return (
          <line
            key={i}
            x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            stroke={active ? "rgba(255, 255, 255, 0.8)" : "rgba(255, 255, 255, 0.35)"}
            strokeWidth={active ? 1.6 : 1}
          />
        );
      })}
      {nodes.map((n) => {
        const nc = COLORS[n.label] || COLORS.Node;
        const active = hover === n.id;
        const r = n.label === "Finding" ? 9 : 7;
        const statusColor = STATUS_COLOR[n.status];
        const gone = n.status === "gone";
        const dashed = gone || n.status === "changed";
        const tip = [n.label, n.title].join(": ")
          + (n.exploitable ? "  ⚠ exploitable" : "")
          + (n.status ? `  (${n.status})` : "");
        return (
          <g
            key={n.id}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover((h) => (h === n.id ? null : h))}
            style={{ cursor: "default", opacity: gone ? 0.5 : 1 }}
          >
            {active && <circle cx={n.x} cy={n.y} r={r + 5} fill={nc.fill} opacity={0.25} />}
            {/* Exploitable ring: a pulsing white halo flags a proven-exploitable service/endpoint or target device. */}
            {n.exploitable && (
              <circle cx={n.x} cy={n.y} r={r + 4} fill="none" stroke={WHITE} strokeWidth={2.2} opacity={0.95} />
            )}
            {/* Cross-run status ring: new / changed / gone from the memory engine. */}
            {statusColor && (
              <circle
                cx={n.x}
                cy={n.y}
                r={r + (n.exploitable ? 7 : 3)}
                fill="none"
                stroke={statusColor}
                strokeWidth={1.4}
                strokeDasharray={dashed ? "3 2" : undefined}
                opacity={0.9}
              />
            )}
            <circle cx={n.x} cy={n.y} r={r} fill={nc.fill} stroke={nc.stroke} strokeWidth={1.5} />
            {n.exploitable && (
              <text x={n.x} y={n.y + 3.5} fontSize={9} textAnchor="middle" fill={nc.stroke} fontWeight={700}>
                !
              </text>
            )}
            <text
              x={n.x + r + 6}
              y={n.y + 4}
              fontSize={11}
              fill={active ? WHITE : "rgba(255, 255, 255, 0.75)"}
              style={{ fontFamily: "var(--mono)" }}
            >
              {n.title}
            </text>
            <title>{tip}</title>
          </g>
        );
      })}
    </svg>
  );
}
```

- [ ] **Step 2: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 3: Grep for required exports and forbidden leftovers**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c 'export const PINK = "#ff2da0";' app/GraphView.tsx
grep -c 'export const WHITE = "#ffffff";' app/GraphView.tsx
grep -c 'fill: PINK, stroke: WHITE' app/GraphView.tsx
grep -c 'fill: WHITE, stroke: PINK' app/GraphView.tsx
grep -c -- '#2d2049\|#1c1330\|#ffc861\|#6fe0b8\|#9683b8\|#8a68b8\|#3a2b57\|#fbf3ec\|#cbb9e3\|#2a1240' app/GraphView.tsx
```
Expected: first four print `1` or more (three `fill: PINK, stroke: WHITE` lines for Engagement/IP/Port/Node, two `fill: WHITE, stroke: PINK` for Service/Finding — so those two greps print `4` and `2` respectively); last line prints `0`.

- [ ] **Step 4: Smoke-test**

Run: `curl -s http://localhost:3000/ | grep -c 'Failed to compile\|Unhandled Runtime Error'`
Expected: `0` (dev server still running from Task 1; `/` still renders the old inline-graph landing page at this point in the sequence, now with the new graph colors).

- [ ] **Step 5: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/app/GraphView.tsx
git commit -m "$(cat <<'EOF'
Recolor graph nodes for the pink/white palette

Solid white fill now marks "pop" node types (Service, Finding) so they
read against the pink canvas; structural types (Engagement, IP, Port)
go hollow — pink fill, white outline — so they recede. Exports PINK/
WHITE as the single source of truth other components reuse.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Nav hover bubble

**Files:**
- Modify: `web/app/Nav.tsx` (full rewrite)
- Modify: `web/app/globals.css` (replace the "Nav" block from Task 1 with bubble rules)

**Interfaces:**
- Consumes: `API_BASE` from `../lib/api` (unchanged import).
- Produces: no new exports — `Nav` remains the default export `web/app/layout.tsx` already renders; its signature (`() => JSX.Element`, no props) is unchanged, so `layout.tsx` needs no edit.

- [ ] **Step 1: Rewrite `web/app/Nav.tsx`**

Replace the entire file with:

```tsx
"use client";
// Floating nav: collapsed to a small tab on the right edge, expands into a link list on hover
// (or focus, for keyboard use) so it never occupies permanent screen space or carries a masthead.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { API_BASE } from "../lib/api";

const LINKS = [
  { href: "/", label: "Home" },
  { href: "/map", label: "Map" },
  { href: "/agent", label: "Agent Chat" },
  { href: "/sast", label: "SAST" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/query", label: "Query" },
  { href: "/guide", label: "Guide" },
];

export default function Nav() {
  const path = usePathname();
  return (
    <nav className="nav-bubble">
      <div className="nav-bubble-panel">
        {LINKS.map((l) => {
          const active = l.href === "/" ? path === "/" : path.startsWith(l.href);
          return (
            <Link key={l.href} href={l.href} className={`nav-bubble-link${active ? " active" : ""}`}>
              {l.label}
            </Link>
          );
        })}
        <a className="nav-bubble-link" href={`${API_BASE}/docs`} target="_blank" rel="noreferrer">
          API Docs ↗
        </a>
      </div>
      <div className="nav-bubble-tab" aria-hidden="true">◉</div>
    </nav>
  );
}
```

- [ ] **Step 2: Replace the Nav block in `web/app/globals.css`**

Find:
```css
/* ---- Nav (docked bar — replaced by .nav-bubble in Task 3) ---- */
.nav {
  position: sticky; top: 0; z-index: 20;
  display: flex; align-items: center; gap: 4px;
  padding: 10px 20px;
  background: rgba(255, 45, 160, 0.9);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border);
}
.brand { display: flex; align-items: center; gap: 9px; font-weight: 750; margin-right: 14px; }
.brand .eye {
  width: 24px; height: 24px; border-radius: 9px; display: grid; place-items: center;
  background: #ffffff;
  color: var(--brand); font-size: 13px;
}
.brand .name { font-size: 14.5px; letter-spacing: -0.01em; }
.nav-link {
  padding: 7px 12px; border-radius: 8px; text-decoration: none;
  color: var(--text-muted); font-weight: 500; transition: background 0.12s, color 0.12s;
}
.nav-link:hover { color: var(--text); background: var(--surface-2); }
.nav-link.active { color: var(--text); background: var(--brand-soft); box-shadow: inset 0 0 0 1px var(--brand-ring); }
```

Replace with:
```css
/* ---- Nav: hover bubble fixed to the right edge ---- */
.nav-bubble {
  position: fixed;
  top: 50%;
  right: 14px;
  transform: translateY(-50%);
  z-index: 30;
  display: flex;
  align-items: center;
  gap: 8px;
}
.nav-bubble-tab {
  width: 34px; height: 34px; flex: none;
  display: grid; place-items: center;
  border-radius: 50%;
  background: #ffffff;
  color: var(--brand);
  font-size: 16px;
}
.nav-bubble-panel {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 2px;
  max-width: 0;
  overflow: hidden;
  opacity: 0;
  background: #ffffff;
  border-radius: var(--radius-sm);
  transition: max-width 0.18s ease, opacity 0.18s ease;
}
.nav-bubble:hover .nav-bubble-panel,
.nav-bubble:focus-within .nav-bubble-panel {
  max-width: 220px;
  opacity: 1;
  padding: 6px;
}
.nav-bubble-link {
  padding: 8px 14px; border-radius: var(--radius-sm); text-decoration: none;
  color: var(--brand); font-weight: 600; font-size: 13px; white-space: nowrap;
}
.nav-bubble-link:hover { background: rgba(255, 45, 160, 0.1); }
.nav-bubble-link.active { background: var(--brand); color: #ffffff; }
```

- [ ] **Step 3: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 4: Grep for required markers and forbidden leftovers**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c 'nav-bubble' app/Nav.tsx
grep -c 'href="/map"' app/Nav.tsx
grep -c 'Pinkeye' app/Nav.tsx
grep -c 'className="brand"\|className="nav-link' app/Nav.tsx
grep -c '^\.nav-bubble {' app/globals.css
grep -c '^\.nav {$\|^\.brand {$' app/globals.css
```
Expected: lines 1–2 print `1` or more; lines 3–4 print `0` (no "Pinkeye" text, no old class names); line 5 prints `1`; line 6 prints `0` (old docked-nav rule blocks removed).

- [ ] **Step 5: Smoke-test — nav renders on an existing page, brand text gone**

Run:
```bash
curl -s http://localhost:3000/dashboard > /tmp/dashboard.html
grep -c 'nav-bubble' /tmp/dashboard.html
grep -c 'Pinkeye' /tmp/dashboard.html
grep -c 'Failed to compile\|Unhandled Runtime Error' /tmp/dashboard.html
```
Expected: first line ≥ `1`, second and third print `0`.

- [ ] **Step 6: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/app/Nav.tsx web/app/globals.css
git commit -m "$(cat <<'EOF'
Replace docked top nav with a hover bubble on the right edge

The nav no longer reserves layout space or carries a "Pinkeye"
masthead — it's a small white tab fixed to the right edge that
expands into the link list on hover/focus. Adds Home (/) and Map
(/map) entries and folds the external API docs link into the same list.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `useLastRun` hook

**Files:**
- Create: `web/lib/useLastRun.ts`

**Interfaces:**
- Consumes: nothing beyond browser `localStorage` (client-only, mirrors `web/lib/useEngagement.ts`'s pattern exactly).
- Produces: `useLastRun(engagementId: string) => { lastRunId: string; setLastRunId: (runId: string) => void }`. Task 5 (`map/page.tsx`) reads `lastRunId`; Task 6 (`page.tsx`) calls `setLastRunId` after `createRun` succeeds.

- [ ] **Step 1: Create `web/lib/useLastRun.ts`**

```tsx
"use client";
// Shared "most recent run" per engagement, persisted in localStorage so it survives navigation
// from the landing page (where a run is launched) to the map page (where its Changes panel lives).
import { useEffect, useState } from "react";

const KEY_PREFIX = "eye.lastRunId.";

export function useLastRun(engagementId: string) {
  const [lastRunId, setLastRunIdState] = useState<string>("");

  useEffect(() => {
    if (typeof window === "undefined" || !engagementId) {
      setLastRunIdState("");
      return;
    }
    setLastRunIdState(localStorage.getItem(KEY_PREFIX + engagementId) || "");
  }, [engagementId]);

  function setLastRunId(runId: string) {
    setLastRunIdState(runId);
    if (typeof window !== "undefined" && engagementId) {
      localStorage.setItem(KEY_PREFIX + engagementId, runId);
    }
  }

  return { lastRunId, setLastRunId };
}
```

- [ ] **Step 2: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 3: Grep for the exported signature**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c 'export function useLastRun(engagementId: string)' lib/useLastRun.ts
grep -c 'KEY_PREFIX = "eye.lastRunId."' lib/useLastRun.ts
```
Expected: both print `1`.

Note: nothing consumes this hook yet, so there's no page-level behavior to curl/screenshot until Task 5 and Task 6 wire it in — Task 7's full sweep is where the cross-page persistence (launch a run on `/`, see its diff on `/map`, survive a refresh) gets verified end-to-end.

- [ ] **Step 4: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/lib/useLastRun.ts
git commit -m "$(cat <<'EOF'
Add useLastRun hook to share the most recent run across pages

Mirrors useEngagement's localStorage pattern, keyed per engagement.
The run is launched on / but its Changes panel now lives on /map, so
lastRunId needs to survive navigation between the two routes.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: New `/map` page (knowledge graph)

**Files:**
- Create: `web/app/map/page.tsx`

**Interfaces:**
- Consumes: `GraphView` default export plus `PINK`, `WHITE` named exports from `../GraphView` (Task 2); `useEngagement()` from `../../lib/useEngagement` (unchanged, returns `{ engagements, selected, select, refresh }`); `useLastRun(selected)` from `../../lib/useLastRun` (Task 4, reads `lastRunId`); `fetchGraph`, `fetchMap`, `fetchChanges`, `type Graph`, `type MemoryChanges` from `../../lib/api` (unchanged); `SectionTitle` from `../ui` (unchanged).
- Produces: the `/map` route. No exports other than the default page component — nothing later depends on this file's internals beyond the route existing (Task 6's eye button links to it).

- [ ] **Step 1: Create `web/app/map/page.tsx`**

```tsx
"use client";
// Knowledge graph: the persisted network map for the active engagement (or every engagement, via
// "full map"), plus the cross-run "what changed" diff for the most recently launched run. Split out
// from the landing page so "/" stays a bare launcher and this page owns the graph full-time.
import { useEffect, useState } from "react";
import GraphView, { PINK, WHITE } from "../GraphView";
import { SectionTitle } from "../ui";
import { fetchChanges, fetchGraph, fetchMap, type Graph, type MemoryChanges } from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";
import { useLastRun } from "../../lib/useLastRun";

const NODE_LEGEND: [string, boolean][] = [
  ["Engagement", false],
  ["IP / Host", false],
  ["Port", false],
  ["Service", true],
  ["Finding", true],
];

const STATUS_LEGEND: [string, string][] = [
  ["⚠ exploitable", "rgba(255,255,255,0.95)"],
  ["new", "rgba(255,255,255,0.95)"],
  ["changed", "rgba(255,255,255,0.55)"],
  ["gone", "rgba(255,255,255,0.3)"],
];

export default function MapPage() {
  const { selected } = useEngagement();
  const { lastRunId } = useLastRun(selected);
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [full, setFull] = useState(false);
  const [changes, setChanges] = useState<MemoryChanges | null>(null);
  const [fullscreen, setFullscreen] = useState(false);

  // Fullscreen map: exit on Esc, and lock body scroll while the overlay is up.
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFullscreen(false);
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [fullscreen]);

  // Poll the graph so new findings appear as scans land. Source depends on the "full map" toggle.
  useEffect(() => {
    const tick = () => {
      const p = full ? fetchMap() : selected ? fetchGraph(selected) : Promise.resolve({ nodes: [], edges: [] });
      p.then(setGraph).catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => clearInterval(t);
  }, [selected, full]);

  // Poll the cross-run memory diff for the most recent run so "what changed since last run" fills in
  // as the run's observations land. Cleared whenever the engagement or tracked run changes.
  useEffect(() => {
    if (!selected || !lastRunId) {
      setChanges(null);
      return;
    }
    const tick = () => {
      fetchChanges(selected, lastRunId).then(setChanges).catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => clearInterval(t);
  }, [selected, lastRunId]);

  const nodeCount = graph.nodes.length;
  const edgeCount = graph.edges.length;

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Knowledge Graph</h1>
          <p className="page-sub">
            Hosts, ports, services, and findings, persisted across runs for the active engagement.
          </p>
        </div>
        <label className="live" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={full} onChange={(e) => setFull(e.target.checked)} />
          full map (all engagements)
        </label>
      </div>

      <SectionTitle
        action={
          <span className="live">
            {nodeCount > 0 && <span className="beat" />}
            {nodeCount} nodes · {edgeCount} edges
            <button
              className="mini-btn"
              onClick={() => setFullscreen(true)}
              title="Expand the map to fill the screen"
            >
              ⤢ Fullscreen
            </button>
          </span>
        }
      >
        Graph
      </SectionTitle>
      <div className={`card graph-card${fullscreen ? " graph-fullscreen" : ""}`} style={{ padding: 12 }}>
        {fullscreen && (
          <button className="mini-btn graph-fs-exit" onClick={() => setFullscreen(false)}>
            ✕ Exit fullscreen (Esc)
          </button>
        )}
        <div className="legend" style={{ padding: "4px 6px 12px" }}>
          {NODE_LEGEND.map(([label, pop]) => (
            <span className="item" key={label}>
              <span
                className="swatch"
                style={
                  pop
                    ? { background: WHITE, border: `1.5px solid ${PINK}` }
                    : { background: PINK, border: `1.5px solid ${WHITE}` }
                }
              />
              {label}
            </span>
          ))}
          {STATUS_LEGEND.map(([label, color]) => (
            <span className="item" key={label}>
              <span
                className="swatch"
                style={{ background: "transparent", boxShadow: `inset 0 0 0 2px ${color}` }}
              />
              {label}
            </span>
          ))}
        </div>
        <GraphView graph={graph} fill={fullscreen} />
        {nodeCount === 0 ? (
          <div className="dim" style={{ textAlign: "center", padding: "12px 0 4px", fontSize: 13 }}>
            No graph data yet — launch a run from the home page to populate hosts, ports, services, and findings.
          </div>
        ) : (
          <div className="dim" style={{ textAlign: "center", padding: "8px 0 2px", fontSize: 11.5 }}>
            drag to pan · scroll to zoom · double-click to reset
          </div>
        )}
      </div>

      {lastRunId && <ChangesPanel changes={changes} />}
    </main>
  );
}

// The cross-run memory diff for the most recent run: new/changed/gone topology and newly-exploitable
// targets, so an operator sees at a glance what this run added over prior knowledge. Fed by the
// /changes endpoint; the same deltas the agent chat surfaces inline.
function ChangesPanel({ changes }: { changes: MemoryChanges | null }) {
  const groups: [string, string, MemoryChanges["added"]][] = changes
    ? [
        ["Newly exploitable", "danger", changes.newly_exploitable],
        ["New", "new", changes.added],
        ["Changed", "changed", changes.changed],
        ["Gone", "gone", changes.removed],
      ]
    : [];
  const total = groups.reduce((n, [, , items]) => n + items.length, 0);
  return (
    <>
      <SectionTitle
        action={
          <span className="live">
            {total > 0 && <span className="beat" />}
            {total} change{total === 1 ? "" : "s"}
          </span>
        }
      >
        Changes since last run
      </SectionTitle>
      <div className="card card-pad">
        {total === 0 ? (
          <div className="dim" style={{ fontSize: 13 }}>
            {changes
              ? "No topology changes recorded for the latest run — the map matched prior knowledge."
              : "Waiting for the latest run's observations…"}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {groups
              .filter(([, , items]) => items.length > 0)
              .map(([label, kind, items]) =>
                items.map((c, i) => (
                  <div
                    key={`${label}-${c.key}-${i}`}
                    className="row"
                    style={{ alignItems: "center", gap: 8, fontSize: 13 }}
                  >
                    <span className={`change-tag change-${kind}`}>{label}</span>
                    <span className="mono">{c.label || c.key}</span>
                  </div>
                ))
              )}
          </div>
        )}
      </div>
    </>
  );
}
```

- [ ] **Step 2: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 3: Grep for required markers**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c 'export default function MapPage' app/map/page.tsx
grep -c 'useLastRun(selected)' app/map/page.tsx
grep -c 'GraphView, { PINK, WHITE }' app/map/page.tsx
```
Expected: all print `1`.

- [ ] **Step 4: Smoke-test the new route**

Run:
```bash
curl -s http://localhost:3000/map > /tmp/map.html
grep -c 'Knowledge Graph' /tmp/map.html
grep -c 'full map (all engagements)' /tmp/map.html
grep -c 'Failed to compile\|Unhandled Runtime Error' /tmp/map.html
```
Expected: first two print `1` or more, third prints `0`.

- [ ] **Step 5: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/app/map/page.tsx
git commit -m "$(cat <<'EOF'
Add dedicated /map page for the knowledge graph

Moves the full-map toggle, node/status legend, GraphView with
fullscreen support, and the "Changes since last run" panel off the
landing page onto their own route, reading the active engagement's
most recent run via useLastRun.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Landing page rewrite — two toggle boxes + "The eye"

**Files:**
- Modify: `web/app/page.tsx` (full rewrite)
- Modify: `web/app/globals.css` (append `.launcher`/`.toggle-box`/`.eye-btn` rules)

**Interfaces:**
- Consumes: `EngagementPicker` from `./EngagementPicker` (unchanged); `createEngagement`, `createRun` from `../lib/api` (unchanged); `useEngagement()` from `../lib/useEngagement` (unchanged); `useLastRun(selected)` from `../lib/useLastRun` (Task 4) — calls its `setLastRunId` after a successful `createRun`; `Link` from `next/link` for the eye button pointing at `/map` (Task 5's route).
- Produces: the `/` route's new default export. Nothing downstream depends on this file's internals.

- [ ] **Step 1: Rewrite `web/app/page.tsx`**

Replace the entire file with:

```tsx
"use client";
// Landing page: pick/launch an engagement, launch a run, or head straight to the knowledge graph.
// Deliberately minimal — no title, no banner, just three centered controls. Detail forms stay
// collapsed until clicked so the page reads as a launcher, not a form.
import { useState } from "react";
import Link from "next/link";
import EngagementPicker from "./EngagementPicker";
import { createEngagement, createRun } from "../lib/api";
import { useEngagement } from "../lib/useEngagement";
import { useLastRun } from "../lib/useLastRun";

const SCAN_TOOLS = ["nmap", "nikto", "nuclei", "ffuf", "tls_cert", "cve_lookup"];
const INTENSITIES = ["light", "normal", "aggressive"];

export default function Home() {
  const { engagements, selected, select, refresh } = useEngagement();
  const { setLastRunId } = useLastRun(selected);
  const [name, setName] = useState("lab-engagement");
  const [cidrs, setCidrs] = useState("10.0.0.0/24");
  const [target, setTarget] = useState("10.0.0.5");
  const [mode, setMode] = useState<"scan" | "agent">("scan");
  const [tool, setTool] = useState("nmap");
  const [intensity, setIntensity] = useState("light");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [engOpen, setEngOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);

  async function onCreate() {
    if (!name.trim()) return;
    setBusy(true);
    setStatus("creating engagement…");
    try {
      const eng = await createEngagement({
        name: name.trim(),
        allowed_cidrs: cidrs.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_domains: [],
      });
      await refresh();
      select(eng.id);
      setStatus(`engagement "${eng.name}" created`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function onScan() {
    if (!selected) return;
    setBusy(true);
    setStatus(mode === "agent" ? "launching agent run (scope-checked)…" : "launching scan (scope-checked)…");
    try {
      const run = await createRun(selected, { target, tool, intensity, mode });
      setLastRunId(run.id);
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="launcher">
      <div className="launcher-row">
        <div className={`toggle-box${engOpen ? " open" : ""}`} onClick={() => setEngOpen((o) => !o)}>
          <span className="toggle-box-icon">◆</span>
          <span className="toggle-box-label">Engagement</span>
        </div>

        <Link href="/map" className="eye-btn">
          <span className="eye-btn-icon">◉</span>
          <span className="eye-btn-label">The eye</span>
        </Link>

        <div className={`toggle-box${runOpen ? " open" : ""}`} onClick={() => setRunOpen((o) => !o)}>
          <span className="toggle-box-icon">▶</span>
          <span className="toggle-box-label">Launch run</span>
        </div>
      </div>

      {(engOpen || runOpen) && (
        <div className="toggle-panel">
          {engOpen && (
            <div className="card card-pad">
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div className="field" style={{ minWidth: 200 }}>
                  <label>Active engagement</label>
                  <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
                </div>
                <div className="field" style={{ flex: 1, minWidth: 180 }}>
                  <label>New engagement name</label>
                  <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-engagement" />
                </div>
                <div className="field" style={{ flex: 1, minWidth: 180 }}>
                  <label>Allowed CIDRs (comma-separated)</label>
                  <input className="input" value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24" />
                </div>
                <button className="btn" onClick={onCreate} disabled={busy || !name.trim()}>
                  Create
                </button>
              </div>
            </div>
          )}

          {runOpen && (
            <div className="card card-pad">
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div className="field" style={{ flex: 1, minWidth: 200 }}>
                  <label>Target (IP / host / URL)</label>
                  <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.5" />
                </div>
                <div className="field" style={{ minWidth: 150 }}>
                  <label>Mode</label>
                  <select className="select" value={mode} onChange={(e) => setMode(e.target.value as "scan" | "agent")}>
                    <option value="scan">Scan — one tool</option>
                    <option value="agent">Agent — LLM plans</option>
                  </select>
                </div>
                {mode === "scan" && (
                  <>
                    <div className="field" style={{ minWidth: 140 }}>
                      <label>Tool</label>
                      <select className="select" value={tool} onChange={(e) => setTool(e.target.value)}>
                        {SCAN_TOOLS.map((t) => (
                          <option key={t} value={t}>{t}</option>
                        ))}
                      </select>
                    </div>
                    <div className="field" style={{ minWidth: 130 }}>
                      <label>Intensity</label>
                      <select className="select" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                        {INTENSITIES.map((i) => (
                          <option key={i} value={i}>{i}</option>
                        ))}
                      </select>
                    </div>
                  </>
                )}
                <button className="btn btn-primary" onClick={onScan} disabled={busy || !selected}>
                  {mode === "agent" ? "Run agent" : `Run ${tool}`}
                </button>
              </div>
              {status && (
                <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>
                  {status}
                </div>
              )}
              {!selected && (
                <div className="dim" style={{ marginTop: 12, fontSize: 13 }}>
                  Select or create an engagement above to enable runs.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </main>
  );
}
```

- [ ] **Step 2: Append toggle-box/eye-button rules to `web/app/globals.css`**

At the end of the file (after the `.sast-engine-hint` rule), append:

```css

/* ---- Landing launcher: two toggle boxes + center "The eye" button ---- */
.launcher {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 28px;
  padding: 32px 24px;
}
.launcher-row {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 40px;
  flex-wrap: wrap;
}
.toggle-box {
  width: 160px; height: 160px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 10px;
  border-radius: var(--radius-lg);
  background: var(--surface-3);
  border: 2px solid var(--border);
  color: var(--text);
  cursor: pointer;
  user-select: none;
  transition: border-color 0.15s, background 0.15s;
}
.toggle-box:hover { background: var(--surface-2); border-color: var(--border-strong); }
.toggle-box.open { border-color: #ffffff; background: var(--surface-2); }
.toggle-box-icon { font-size: 30px; }
.toggle-box-label {
  font-size: 12.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;
}
.toggle-panel {
  display: flex; flex-wrap: wrap; gap: 16px; justify-content: center;
  width: 100%; max-width: 1160px;
}
.toggle-panel .card { flex: 1; min-width: 320px; }

.eye-btn {
  width: 190px; height: 190px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 10px;
  border-radius: var(--radius-lg);
  background: #ffffff;
  color: var(--brand);
  text-decoration: none;
  cursor: pointer;
  transition: background 0.15s;
}
.eye-btn:hover { background: #ffeaf5; }
.eye-btn-icon { font-size: 44px; }
.eye-btn-label {
  font-size: 15px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em;
}
```

- [ ] **Step 3: Typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 4: Grep for required markers and removed content**

Run:
```bash
cd /home/samosa/Pinkeye/web
grep -c 'className="launcher"' app/page.tsx
grep -c 'href="/map"' app/page.tsx
grep -c 'The eye' app/page.tsx
grep -c 'toggle-box' app/page.tsx
grep -c 'Network Map\|Authorized use only\|Knowledge graph' app/page.tsx
grep -c '\.launcher {' app/globals.css
grep -c '\.toggle-box {' app/globals.css
grep -c '\.eye-btn {' app/globals.css
```
Expected: lines 1–4 and 6–8 print `1` or more; line 5 prints `0` (old title/banner/graph-section copy is gone).

- [ ] **Step 5: Smoke-test the landing page**

Run:
```bash
curl -s http://localhost:3000/ > /tmp/landing.html
grep -c 'The eye' /tmp/landing.html
grep -c 'toggle-box' /tmp/landing.html
grep -c 'Network Map\|Authorized use only' /tmp/landing.html
grep -c 'Failed to compile\|Unhandled Runtime Error' /tmp/landing.html
```
Expected: first two print `1` or more; last two print `0`.

- [ ] **Step 6: Commit**

```bash
cd /home/samosa/Pinkeye
git add web/app/page.tsx web/app/globals.css
git commit -m "$(cat <<'EOF'
Rewrite landing page as two toggle boxes + "The eye" button

/ is now a bare, centered launcher: an Engagement box and a
Launch-a-run box (forms collapsed until clicked, no step numbering,
no title/banner) flanking a center button that links straight to the
new /map page. Graph and engagement/run forms no longer share a page.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Full verification sweep

**Files:** none (verification only — may produce a small fixup commit if this task finds something Tasks 1–6 missed).

**Interfaces:** none produced; this task consumes the running app as a black box.

- [ ] **Step 1: Whole-project typecheck**

Run: `cd /home/samosa/Pinkeye/web && npx tsc --noEmit -p tsconfig.json; echo "exit:$?"`
Expected: `exit:0`.

- [ ] **Step 2: Ensure the dev server is up**

Run:
```bash
curl -sf http://localhost:3000/ >/dev/null 2>&1 || {
  cd /home/samosa/Pinkeye/web
  nohup npm run dev > /tmp/pinkeye-dev.log 2>&1 & disown
  timeout 40 bash -c 'until curl -sf http://localhost:3000/ >/dev/null; do sleep 1; done'
}
echo ready
```
Expected: prints `ready`.

- [ ] **Step 3: Curl-smoke every route**

Run:
```bash
for route in / /map /agent /sast /dashboard /query /guide; do
  code=$(curl -s -o /tmp/route.html -w '%{http_code}' "http://localhost:3000${route}")
  errs=$(grep -c 'Failed to compile\|Unhandled Runtime Error' /tmp/route.html)
  echo "${route} -> http ${code}, compile-errors ${errs}"
done
```
Expected: every route prints `http 200, compile-errors 0`.

- [ ] **Step 4: Confirm palette/structure markers across routes**

Run:
```bash
curl -s http://localhost:3000/ | grep -c 'The eye\|toggle-box'
curl -s http://localhost:3000/map | grep -c 'Knowledge Graph\|full map'
curl -s http://localhost:3000/dashboard | grep -c 'nav-bubble'
curl -s http://localhost:3000/dashboard | grep -c 'Pinkeye'
```
Expected: first three print `1` or more; the last (brand text on an unrelated page) prints `0`.

- [ ] **Step 5: Best-effort visual screenshot pass (optional — do not block on this)**

Run:
```bash
mkdir -p /tmp/pinkeye-shots
node -e "require.resolve('playwright')" 2>/dev/null && HAVE_PW=1 || HAVE_PW=0
if [ "$HAVE_PW" = "0" ]; then
  cd /tmp/pinkeye-shots && npm init -y >/dev/null 2>&1 && npm install playwright@1.61.1 >/tmp/pw-install.log 2>&1
fi
CHROME=$(find "$HOME/.cache/ms-playwright" -maxdepth 1 -iname 'chromium-*' -type d 2>/dev/null | head -1)/chrome-linux64/chrome
if [ ! -x "$CHROME" ]; then
  npx --prefix /tmp/pinkeye-shots playwright install chromium >/tmp/pw-browser-install.log 2>&1 || echo "no network for browser download — skipping screenshot pass"
fi
```
Expected: either a usable Chromium ends up available, or the script prints the "no network" line — in that case, skip the rest of this step and rely on Steps 3–4 as sufficient evidence; don't treat a missing browser as a task failure.

If Chromium is available, run (adjust `executablePath` to whatever Step 5 found):
```bash
cat > /tmp/pinkeye-shots/shot.js <<'EOF'
const { chromium } = require('playwright');
const routes = ['/', '/map', '/agent', '/sast', '/dashboard', '/query', '/guide'];
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  for (const r of routes) {
    await page.goto(`http://localhost:3000${r}`, { waitUntil: 'load', timeout: 30000 });
    await page.waitForTimeout(400);
    await page.screenshot({ path: `/tmp/pinkeye-shots${r === '/' ? '/home' : r.replace(/\//g, '_')}.png`, fullPage: true });
  }
  // Nav bubble hover state, and a toggle box opened, on the landing page.
  await page.goto('http://localhost:3000/', { waitUntil: 'load' });
  await page.hover('.nav-bubble-tab');
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/pinkeye-shots/nav_hover.png' });
  await page.click('.toggle-box >> nth=0');
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/pinkeye-shots/toggle_open.png' });
  await browser.close();
})();
EOF
cd /tmp/pinkeye-shots && node shot.js
```
Expected: a set of `.png` files under `/tmp/pinkeye-shots/`. Open/read each one and confirm by eye: solid shocking-pink background (no black/dark surfaces anywhere), white text and borders, no drop-shadows, the nav bubble panel visible in `nav_hover.png`, the clicked toggle box's form panel visible in `toggle_open.png`, and the graph on `map.png` rendering white "pop" nodes / hollow pink-outline nodes against the pink canvas.

- [ ] **Step 6: Fix anything Step 5 reveals, or confirm clean**

If the screenshots show a leftover dark/old-palette element, find and fix it in the relevant file from Tasks 1–6, re-run that task's grep check, and commit the fix with a message describing what was missed (e.g. `git commit -m "Fix leftover dark surface in X missed by Task N"`). If nothing is wrong, no commit is needed for this step.

- [ ] **Step 7: Stop the dev server**

Run: `pkill -f "next dev" 2>/dev/null; echo stopped`
Expected: prints `stopped` (best-effort; fine if nothing matched).

---

## Self-Review Notes

- **Spec coverage:** Section 1 (palette) → Tasks 1, 2, and the new-component colors added in Tasks 3/6. Section 2 (nav bubble) → Task 3. Section 3 (landing page) → Task 6. Section 4 (map page) → Task 5. Section 5 (`lastRunId` sharing) → Task 4, consumed in Tasks 5–6. Out-of-scope pages are intentionally untouched beyond the shared tokens from Task 1, confirmed structurally unchanged in Task 7 Step 4's `dashboard` check.
- **Type consistency:** `useLastRun(engagementId: string) => { lastRunId, setLastRunId }` is defined in Task 4 and consumed with matching destructuring in Task 5 (`{ lastRunId }`) and Task 6 (`{ setLastRunId }`). `GraphView`'s `PINK`/`WHITE` named exports from Task 2 are imported by exact name in Task 5. `useEngagement()`'s `{ engagements, selected, select, refresh }` shape is unchanged from the existing hook and used identically in Task 6.
- **No placeholders:** every task ships complete file contents or complete diffs, not descriptions of changes.
