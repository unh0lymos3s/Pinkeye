#!/usr/bin/env node
// Regenerates the Pinkeye wordmark inside docs/index.html, splicing fresh <svg> rows between the
// `banner:start` / `banner:end` markers and leaving the rest of the file untouched.
//
//   node docs/tools/build-banner.mjs
//
// This is the site's only build step, and it only needs re-running when the wordmark art or the
// glyph font below changes. Everything else in docs/ is already the deployable artifact.
//
// The glyph font is a copy of web/app/AsciiBanner.tsx's — the operator UI draws these rects at
// runtime, the static site bakes them in. If you change one, change both.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ASCII_LOGO = [
  "██████╗ ██╗███╗   ██╗██╗  ██╗███████╗██╗   ██╗███████╗",
  "██╔══██╗██║████╗  ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝",
  "██████╔╝██║██╔██╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗  ",
  "██╔═══╝ ██║██║╚██╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  ",
  "██║     ██║██║ ╚████║██║  ██╗███████╗   ██║   ███████╗",
  "╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝",
];

// The wordmark is built from Unicode box-drawing/block characters (█ ═ ║ ╔ ╗ ╚ ╝). Rendering those
// as real text is unreliable: browsers fall back to whatever installed font actually has glyphs for
// those codepoints, and that fallback's cell metrics don't always match the base monospace font —
// so the grid drifts out of alignment, differently per OS/browser and even per zoom level. Drawing
// it as vector rects instead sidesteps fonts entirely: same pixels everywhere, any zoom/width.
const CELL_W = 60;
const CELL_H = 100;
const H1 = [36, 45]; // upper horizontal bar (y0, y1)
const H2 = [55, 64]; // lower horizontal bar
const V1 = [18, 27]; // left vertical bar (x0, x1)
const V2 = [33, 42]; // right vertical bar
const MID_X = CELL_W / 2;
const MID_Y = CELL_H / 2;

function glyphRects(ch) {
  switch (ch) {
    case "█":
      return [{ x: 0, y: 0, w: CELL_W, h: CELL_H }];
    case "═":
      return [
        { x: 0, y: H1[0], w: CELL_W, h: H1[1] - H1[0] },
        { x: 0, y: H2[0], w: CELL_W, h: H2[1] - H2[0] },
      ];
    case "║":
      return [
        { x: V1[0], y: 0, w: V1[1] - V1[0], h: CELL_H },
        { x: V2[0], y: 0, w: V2[1] - V2[0], h: CELL_H },
      ];
    case "╔":
      return [
        { x: V1[0], y: MID_Y, w: V1[1] - V1[0], h: CELL_H - MID_Y },
        { x: V2[0], y: MID_Y, w: V2[1] - V2[0], h: CELL_H - MID_Y },
        { x: MID_X, y: H1[0], w: CELL_W - MID_X, h: H1[1] - H1[0] },
        { x: MID_X, y: H2[0], w: CELL_W - MID_X, h: H2[1] - H2[0] },
      ];
    case "╗":
      return [
        { x: V1[0], y: MID_Y, w: V1[1] - V1[0], h: CELL_H - MID_Y },
        { x: V2[0], y: MID_Y, w: V2[1] - V2[0], h: CELL_H - MID_Y },
        { x: 0, y: H1[0], w: MID_X, h: H1[1] - H1[0] },
        { x: 0, y: H2[0], w: MID_X, h: H2[1] - H2[0] },
      ];
    case "╚":
      return [
        { x: V1[0], y: 0, w: V1[1] - V1[0], h: MID_Y },
        { x: V2[0], y: 0, w: V2[1] - V2[0], h: MID_Y },
        { x: MID_X, y: H1[0], w: CELL_W - MID_X, h: H1[1] - H1[0] },
        { x: MID_X, y: H2[0], w: CELL_W - MID_X, h: H2[1] - H2[0] },
      ];
    case "╝":
      return [
        { x: V1[0], y: 0, w: V1[1] - V1[0], h: MID_Y },
        { x: V2[0], y: 0, w: V2[1] - V2[0], h: MID_Y },
        { x: 0, y: H1[0], w: MID_X, h: H1[1] - H1[0] },
        { x: 0, y: H2[0], w: MID_X, h: H2[1] - H2[0] },
      ];
    default:
      return []; // spaces (and anything unmapped) draw nothing
  }
}

const COLS = ASCII_LOGO[0].length;
// One <svg> per row rather than one for the whole wordmark: the wave animation staggers a per-row
// animation-delay across them (see .ascii-row in styles.css), which needs separate elements.
const rows = ASCII_LOGO.map((line, r) => {
  const rects = Array.from(line).flatMap((ch, c) =>
    glyphRects(ch).map((g) => `<rect x="${c * CELL_W + g.x}" y="${g.y}" width="${g.w}" height="${g.h}"/>`)
  );
  return (
    `      <svg class="ascii-row" style="animation-delay:${(r * 0.12).toFixed(2)}s" ` +
    `viewBox="0 0 ${COLS * CELL_W} ${CELL_H}" preserveAspectRatio="xMidYMid meet">${rects.join("")}</svg>`
  );
}).join("\n");

const indexPath = fileURLToPath(new URL("../index.html", import.meta.url));
const html = readFileSync(indexPath, "utf8");
const START = /( *<!-- banner:start[^>]*-->\n)[\s\S]*?( *<!-- banner:end -->)/;
if (!START.test(html)) {
  console.error("banner:start / banner:end markers not found in docs/index.html");
  process.exit(1);
}
writeFileSync(indexPath, html.replace(START, `$1${rows}\n$2`));
console.log(`docs/index.html: wrote ${ASCII_LOGO.length} banner rows`);
