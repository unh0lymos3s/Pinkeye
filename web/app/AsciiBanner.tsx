// The Pinkeye ANSI/block-art wordmark, shared by the operator landing page (app/page.tsx) and the
// public product page (app/product/page.tsx) so both always render the identical banner.
//
// Each line renders as its own row so the wave animation (globals.css .ascii-row) can stagger a
// per-row animation-delay across them. This is the one place to edit the art — see glyphRects()
// below for why it's drawn as vector rects instead of as the literal characters.
const ASCII_LOGO = [
  "██████╗ ██╗███╗   ██╗██╗  ██╗███████╗██╗   ██╗███████╗",
  "██╔══██╗██║████╗  ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝",
  "██████╔╝██║██╔██╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗  ",
  "██╔═══╝ ██║██║╚██╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  ",
  "██║     ██║██║ ╚████║██║  ██╗███████╗   ██║   ███████╗",
  "╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝",
];

// The wordmark is built from Unicode box-drawing/block characters (█ ═ ║ ╔ ╗ ╚ ╝). Rendering
// those as real text is unreliable: browsers fall back to whatever installed font actually has
// glyphs for those codepoints, and that fallback's cell metrics don't always match the base
// monospace font — so the grid drifts out of alignment, differently per OS/browser and even per
// zoom level (font fallback can change at different rendered sizes). Drawing it as vector rects
// instead sidesteps fonts entirely: same pixels everywhere, scales exactly at any zoom/width.
const CELL_W = 60;
const CELL_H = 100;
const H1: [number, number] = [36, 45]; // upper horizontal bar (y0, y1)
const H2: [number, number] = [55, 64]; // lower horizontal bar
const V1: [number, number] = [18, 27]; // left vertical bar (x0, x1)
const V2: [number, number] = [33, 42]; // right vertical bar
const MID_X = CELL_W / 2;
const MID_Y = CELL_H / 2;

type Rect = { x: number; y: number; w: number; h: number };

function glyphRects(ch: string): Rect[] {
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
      return [];
  }
}

const ASCII_COLS = ASCII_LOGO[0].length;

export default function AsciiBanner() {
  return (
    <div className="ascii-banner-wrap">
      <div className="ascii-banner" aria-hidden="true">
        {ASCII_LOGO.map((line, r) => (
          <svg
            key={r}
            className="ascii-row"
            style={{ animationDelay: `${r * 0.12}s` }}
            viewBox={`0 0 ${ASCII_COLS * CELL_W} ${CELL_H}`}
            preserveAspectRatio="xMidYMid meet"
          >
            {Array.from(line).flatMap((ch, c) =>
              glyphRects(ch).map((rect, i) => (
                <rect key={`${c}-${i}`} x={c * CELL_W + rect.x} y={rect.y} width={rect.w} height={rect.h} />
              ))
            )}
          </svg>
        ))}
      </div>
    </div>
  );
}
