"use client";
// A real 3D eyeball (not a flat icon), freshly plucked from its socket — it trails a fleshy
// optic-nerve stalk behind it — that tracks the cursor. The one deliberate departure from the rest
// of the app's flat, shadow-free "shocking pink + white" design system. Floats freely on the page
// (no boxed-in background — see globals.css .eye-btn/.eye-orb) so it reads as a round orb rather
// than an icon inside a square card. Bare orb only: no eyelid, no glare/highlight.
//
// Scene graph:
//   scene
//   ├─ ambient + directional key + soft fill light
//   ├─ eyeGroup (the WHOLE ball rotates to track the cursor — the sclera/veins follow the gaze)
//   │  ├─ sclera (sphere, bloodshot "pink eye" base texture — the app's own namesake)
//   │  ├─ pulse shell (barely-larger transparent sphere carrying the red bloom + engorged trunk
//   │  │   vessels; its opacity throbs on a heartbeat so the irritation visibly pulses)
//   │  └─ iris / pupil / cornea (flat discs + clear clearcoat dome, same layering as before)
//   └─ tailGroup (the optic-nerve stalk, pivoted at the origin like the eye but easing toward the
//       eye's rotation more slowly, so it drags behind gaze changes and dangles when idle)
//
// Dynamics (all timers in plain locals — never React state):
//   - saccades: big target jumps snap fast, then settle slowly (two-speed ease)
//   - micro-saccades: tiny random fixation offsets every ~0.6–2.5s
//   - idle wander: after 3s without mouse movement the eye looks around on its own
//   - pupil: slow hippus oscillation + constricts as the cursor approaches, dilates when far
//   - vein pulse: the redness layer throbs at ~55bpm (sharp attack, slow decay)
import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

// Rendered larger than the 160px click target so the orb overflows it, staying round. 310 (up from
// 250) plus the camera pulled back to z=5.2 (see below): together these keep the ball's on-screen
// diameter close to what it was (~189px vs ~198px before) while opening up enough frustum below
// and behind the ball for the optic-nerve tail to droop into view without being cropped.
const SIZE = 310;
const MAX_DEFLECTION = THREE.MathUtils.degToRad(28); // clamp so the iris never turns past the front hemisphere
const NORMALIZE_PX = 460; // cursor distance (px) at which the eye is already at max deflection
// Two-speed gaze ease: real eyes move in saccades — a fast ballistic snap toward a new target,
// then a slow settle/drift during fixation — not a single constant lerp.
const SACCADE_EASE = 0.35;
const SETTLE_EASE = 0.08;
const SACCADE_START = THREE.MathUtils.degToRad(6); // target error that triggers the fast snap
const SACCADE_END = THREE.MathUtils.degToRad(1); // error below which we drop back to settle speed
const TAIL_EASE = 0.05; // slower than the eye so the stalk visibly lags/drags behind gaze changes
// The tail chases only a fraction of the eye's rotation — dangling flesh has inertia and doesn't
// pivot as far as the ball it hangs off — which also keeps the swinging tip inside the frustum at
// max deflection (verified by projecting every tail vertex at worst-case gaze + sway: NDC ≤ 0.98).
const TAIL_FOLLOW = 0.7;
const IDLE_MS = 3000; // no mouse movement for this long → the eye starts wandering on its own
// Apparent depth of the iris behind the corneal surface, faked by nudging the iris/pupil discs
// against the gaze each frame instead of physically recessing them (see the animate loop). The
// max nudge, sin(MAX_DEFLECTION)·IRIS_RECESS ≈ 0.056, must stay under the ~0.08 gap between the
// iris disc (r=0.42) and the cornea rim (r≈0.5) so the iris never slides out from under the dome.
const IRIS_RECESS = 0.12;
const PULSE_MS = 1090; // ~55bpm heartbeat for the vein-pulse layer

// One drawn vessel segment. Vessels are grown first (geometry only) and stroked afterwards, so the
// exact same paths can be drawn twice: once blurred/dark (the vessel seen through the translucent
// conjunctiva) and once sharp on top (its surface portion) — that under-glow is what makes canvas
// veins read as *in* the tissue instead of painted on it.
type VesselSeg = { x0: number; y0: number; mx: number; my: number; x1: number; y1: number; w: number };

// Grows one vessel as a random walk toward the limbus (the texture's center, where the front of the
// eye maps): short segments with angular noise (tortuosity), width tapering every step, and a
// chance to fork a thinner child branch — real dichotomous branching — until it thins out into a
// capillary tip or reaches the iris zone.
function growVessel(size: number, x: number, y: number, angle: number, width: number, segs: VesselSeg[]) {
  let px = x;
  let py = y;
  let a = angle;
  let w = width;
  let guard = 0;
  while (w > 0.35 && guard++ < 60) {
    const segLen = size * (0.008 + Math.random() * 0.012);
    // steer gently toward the limbus, with per-segment wobble so the path meanders
    const toCenter = Math.atan2(size / 2 - py, size / 2 - px);
    let da = toCenter - a;
    da = Math.atan2(Math.sin(da), Math.cos(da)); // wrap to [-π, π] so steering takes the short way
    a += da * 0.14 + (Math.random() - 0.5) * 0.6;
    const nx = px + Math.cos(a) * segLen;
    const ny = py + Math.sin(a) * segLen;
    const mx = (px + nx) / 2 + (Math.random() - 0.5) * segLen * 0.5;
    const my = (py + ny) / 2 + (Math.random() - 0.5) * segLen * 0.5;
    segs.push({ x0: px, y0: py, mx, my, x1: nx, y1: ny, w });
    px = nx;
    py = ny;
    w *= 0.9 + Math.random() * 0.07;
    if (w > 0.5 && Math.random() < 0.12 + (1 - w / width) * 0.08) {
      const side = Math.random() < 0.5 ? -1 : 1;
      growVessel(size, px, py, a + side * (0.45 + Math.random() * 0.45), w * 0.6, segs);
    }
    if (Math.hypot(px - size / 2, py - size / 2) < size * 0.055) break; // reached the iris zone
  }
}

function strokeVesselPath(ctx: CanvasRenderingContext2D, s: VesselSeg) {
  ctx.beginPath();
  ctx.moveTo(s.x0, s.y0);
  ctx.quadraticCurveTo(s.mx, s.my, s.x1, s.y1);
  ctx.stroke();
}

// Two-pass vessel rendering: a blurred deep-maroon under-layer, then the sharp surface strokes.
function strokeVessels(ctx: CanvasRenderingContext2D, segs: VesselSeg[]) {
  ctx.lineCap = "round";
  ctx.save();
  ctx.filter = "blur(2px)";
  for (const s of segs) {
    ctx.strokeStyle = `rgba(143, 10, 24, ${Math.min(0.5, 0.12 + s.w * 0.1)})`;
    ctx.lineWidth = s.w * 1.9;
    strokeVesselPath(ctx, s);
  }
  ctx.restore();
  for (const s of segs) {
    // thin surface capillaries run brighter red; thick engorged trunks a deeper red
    ctx.strokeStyle =
      s.w < 1.2
        ? `rgba(224, 32, 44, ${Math.min(0.8, 0.35 + s.w * 0.2)})`
        : `rgba(178, 10, 24, ${Math.min(0.85, 0.35 + s.w * 0.14)})`;
    ctx.lineWidth = s.w;
    strokeVesselPath(ctx, s);
  }
}

// Draws the sclera's base texture: near-white with a faint red flush and the fine capillary web.
// The heavy "infected" elements — the strong red bloom and the thick engorged trunk vessels — live
// on the separate pulse-layer texture (makePulseTexture) so their opacity can throb; the faint
// bloom kept here guarantees the eye never looks healthy even at the pulse's minimum.
function makeScleraTexture(): THREE.CanvasTexture {
  const size = 1024;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;

  // The sclera/pulse sphere geometries are rotated (see rotateY at their creation) so this
  // texture's center lands on the front of the ball where the iris sits, with the poles at the
  // vertical edges — so vessels grown toward the canvas center run from the back of the ball
  // forward to the limbus. Keep the base itself close to true white
  // — the "infected" read needs to come from clearly red veins/bloom against white, not from tinting
  // the whole sclera tan/beige (that reads as an off-color material, not redness).
  ctx.fillStyle = "#fdfbfa";
  ctx.fillRect(0, 0, size, size);
  const vGrad = ctx.createLinearGradient(0, 0, 0, size);
  vGrad.addColorStop(0.0, "#f3ded9");
  vGrad.addColorStop(0.32, "#fdf9f8");
  vGrad.addColorStop(0.5, "#ffffff");
  vGrad.addColorStop(0.68, "#fdf9f8");
  vGrad.addColorStop(1.0, "#f3ded9");
  ctx.fillStyle = vGrad;
  ctx.fillRect(0, 0, size, size);
  const bloom = ctx.createRadialGradient(size / 2, size / 2, size * 0.02, size / 2, size / 2, size * 0.48);
  bloom.addColorStop(0, "rgba(215, 15, 30, 0.32)");
  bloom.addColorStop(0.45, "rgba(220, 30, 40, 0.16)");
  bloom.addColorStop(0.8, "rgba(220, 40, 50, 0.05)");
  bloom.addColorStop(1, "rgba(220, 40, 50, 0)");
  ctx.fillStyle = bloom;
  ctx.fillRect(0, 0, size, size);

  // Background capillary web: many thin vessels seeded on a wide ring around the front, all growing
  // inward toward the limbus ("ciliary injection" — the vessel pattern of an irritated eye).
  const segs: VesselSeg[] = [];
  const fieldTrunks = 60;
  for (let i = 0; i < fieldTrunks; i++) {
    const ang = Math.random() * Math.PI * 2;
    const rr = size * (0.3 + Math.random() * 0.2);
    const sx = size / 2 + Math.cos(ang) * rr;
    const sy = size / 2 + Math.sin(ang) * rr;
    growVessel(size, sx, sy, ang + Math.PI + (Math.random() - 0.5) * 0.8, 1 + Math.random() * 1.1, segs);
  }
  strokeVessels(ctx, segs);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  texture.needsUpdate = true;
  return texture;
}

// The throbbing part of the bloodshot look, on its own transparent texture: the strong red bloom
// concentrated at the limbus plus a handful of thick engorged trunk vessels. Mapped onto a shell
// sphere a hair larger than the sclera whose material opacity beats in the render loop.
function makePulseTexture(): THREE.CanvasTexture {
  const size = 1024;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;

  const bloom = ctx.createRadialGradient(size / 2, size / 2, size * 0.02, size / 2, size / 2, size * 0.48);
  bloom.addColorStop(0, "rgba(215, 15, 30, 0.75)");
  bloom.addColorStop(0.45, "rgba(220, 30, 40, 0.4)");
  bloom.addColorStop(0.8, "rgba(220, 40, 50, 0.12)");
  bloom.addColorStop(1, "rgba(220, 40, 50, 0)");
  ctx.fillStyle = bloom;
  ctx.fillRect(0, 0, size, size);

  const segs: VesselSeg[] = [];
  const trunks = 26;
  for (let i = 0; i < trunks; i++) {
    const ang = Math.random() * Math.PI * 2;
    const rr = size * (0.42 + Math.random() * 0.08);
    const sx = size / 2 + Math.cos(ang) * rr;
    const sy = size / 2 + Math.sin(ang) * rr;
    growVessel(size, sx, sy, ang + Math.PI + (Math.random() - 0.5) * 0.5, 3 + Math.random() * 2, segs);
  }
  strokeVessels(ctx, segs);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  texture.needsUpdate = true;
  return texture;
}

// Draws the iris texture in the brand-pink family with real anatomical structure: a multi-stop
// radial gradient that shifts across several pink/magenta tones (not one flat pink), angular color
// variation (wedge sectors of lighter/deeper pink), a lighter collarette ring around the pupil,
// dense radial fibers in both dark and light, and — the key "reads as human" cue — a dark limbal
// ring baked in at the outer edge.
function makeIrisTexture(): THREE.CanvasTexture {
  const size = 512;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2;

  // Base radial gradient: dark magenta pupil margin → dominant brand pink → hot-pink highlight band
  // → darkening toward the limbus → dark limbal ring. Pink stays the unambiguous dominant hue.
  const g = ctx.createRadialGradient(cx, cy, r * 0.06, cx, cy, r);
  g.addColorStop(0.0, "#7d0d4b");
  g.addColorStop(0.16, "#c21a76");
  g.addColorStop(0.4, "#ff2da0"); // brand pink, the dominant tone
  g.addColorStop(0.62, "#ff56b3");
  g.addColorStop(0.8, "#d8237f");
  g.addColorStop(0.92, "#5c0a37");
  g.addColorStop(0.98, "#26031a");
  g.addColorStop(1.0, "#1a0212");
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  // Angular color variation: soft wedge sectors alternating a lighter and a deeper pink, so the
  // iris has hue/tone variation around its circumference rather than perfect radial symmetry.
  const sectors = 22;
  for (let i = 0; i < sectors; i++) {
    const a0 = (i / sectors) * Math.PI * 2 + Math.random() * 0.1;
    const a1 = a0 + (Math.PI * 2) / sectors + Math.random() * 0.08;
    const light = i % 2 === 0;
    ctx.fillStyle = light
      ? `rgba(255, 138, 205, ${0.05 + Math.random() * 0.07})`
      : `rgba(150, 18, 92, ${0.06 + Math.random() * 0.08})`;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r * 0.9, a0, a1);
    ctx.closePath();
    ctx.fill();
  }

  // Radial fibers: dense, thin, both darker-than-base and lighter-than-base for depth.
  const fiberCount = 240;
  for (let i = 0; i < fiberCount; i++) {
    const angle = (i / fiberCount) * Math.PI * 2 + (Math.random() - 0.5) * 0.14;
    const inner = r * (0.2 + Math.random() * 0.12);
    const outer = r * (0.72 + Math.random() * 0.18);
    const light = Math.random() > 0.55;
    ctx.strokeStyle = light
      ? `rgba(255, 170, 220, ${0.05 + Math.random() * 0.12})`
      : `rgba(28, 4, 18, ${0.07 + Math.random() * 0.16})`;
    ctx.lineWidth = 0.5 + Math.random() * 0.9;
    const midR = (inner + outer) / 2;
    const jitter = (Math.random() - 0.5) * 0.06;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(angle) * inner, cy + Math.sin(angle) * inner);
    ctx.quadraticCurveTo(
      cx + Math.cos(angle + jitter) * midR,
      cy + Math.sin(angle + jitter) * midR,
      cx + Math.cos(angle) * outer,
      cy + Math.sin(angle) * outer
    );
    ctx.stroke();
  }

  // Collarette: the slightly raised, lighter ring where the pupillary and ciliary zones meet.
  ctx.strokeStyle = "rgba(255, 150, 210, 0.35)";
  ctx.lineWidth = r * 0.03;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.32, 0, Math.PI * 2);
  ctx.stroke();

  // A few crypts/blotches near the pupil for organic irregularity.
  for (let i = 0; i < 14; i++) {
    const a = Math.random() * Math.PI * 2;
    const rr = r * (0.24 + Math.random() * 0.14);
    ctx.fillStyle = `rgba(60, 6, 38, ${0.1 + Math.random() * 0.14})`;
    ctx.beginPath();
    ctx.ellipse(cx + Math.cos(a) * rr, cy + Math.sin(a) * rr, r * 0.02 + Math.random() * r * 0.03, r * 0.015 + Math.random() * r * 0.02, a, 0, Math.PI * 2);
    ctx.fill();
  }

  // Explicit dark limbal ring at the very edge — the single most important "human eye" cue.
  ctx.strokeStyle = "rgba(14, 1, 9, 0.85)";
  ctx.lineWidth = r * 0.055;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.955, 0, Math.PI * 2);
  ctx.stroke();
  ctx.strokeStyle = "rgba(14, 1, 9, 0.4)";
  ctx.lineWidth = r * 0.03;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.9, 0, Math.PI * 2);
  ctx.stroke();

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  texture.needsUpdate = true;
  return texture;
}

// Fleshy texture for the optic-nerve stalk. TubeGeometry maps u (canvas x) along the tube's length
// and v (canvas y) around its circumference, so "lengthwise" muscle-fiber striations are wavy
// horizontal lines, and the tip (u=1, the canvas's right edge) darkens toward a torn-off stump.
function makeNerveTexture(): THREE.CanvasTexture {
  const w = 512;
  const h = 256;
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d")!;

  ctx.fillStyle = "#c4404f";
  ctx.fillRect(0, 0, w, h);

  // lengthwise striations: alternating darker sinew and lighter glisten lines with gentle waviness
  const striations = 46;
  for (let i = 0; i < striations; i++) {
    const y = Math.random() * h;
    const light = Math.random() > 0.6;
    ctx.strokeStyle = light
      ? `rgba(236, 130, 140, ${0.1 + Math.random() * 0.18})`
      : `rgba(122, 22, 34, ${0.12 + Math.random() * 0.22})`;
    ctx.lineWidth = 1 + Math.random() * 2.4;
    ctx.lineCap = "round";
    ctx.beginPath();
    ctx.moveTo(0, y);
    const wobble = 4 + Math.random() * 8;
    for (let x = 0; x <= w; x += w / 8) {
      ctx.lineTo(x, y + Math.sin(x * 0.02 + i) * wobble);
    }
    ctx.stroke();
  }

  // a few fine dark vessels snaking along the stalk
  for (let i = 0; i < 8; i++) {
    let y = Math.random() * h;
    ctx.strokeStyle = `rgba(90, 8, 20, ${0.35 + Math.random() * 0.3})`;
    ctx.lineWidth = 1 + Math.random() * 1.4;
    ctx.beginPath();
    ctx.moveTo(0, y);
    for (let x = 0; x <= w; x += w / 10) {
      y += (Math.random() - 0.5) * 22;
      ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  // darken toward the ragged free end
  const tip = ctx.createLinearGradient(0, 0, w, 0);
  tip.addColorStop(0.0, "rgba(60, 8, 16, 0)");
  tip.addColorStop(0.8, "rgba(60, 8, 16, 0)");
  tip.addColorStop(1.0, "rgba(60, 8, 16, 0.6)");
  ctx.fillStyle = tip;
  ctx.fillRect(0, 0, w, h);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  texture.needsUpdate = true;
  return texture;
}

// Builds the tapered optic-nerve stalk: a tube swept along a curve that exits the back pole and
// droops down past the bottom of the ball. TubeGeometry is constant-radius, so each cross-section
// ring is scaled toward its curve centerpoint afterwards — full radius at the root shrinking to a
// ragged stump at the free end. The root ring starts *inside* the radius-1 sclera so the join is
// always hidden by the ball itself at any gaze angle.
function makeTailGeometry(): THREE.TubeGeometry {
  const curve = new THREE.CatmullRomCurve3([
    new THREE.Vector3(0, 0.03, -0.72),
    new THREE.Vector3(0.04, -0.32, -1.08),
    new THREE.Vector3(0.12, -0.82, -0.95),
    new THREE.Vector3(0.18, -1.45, -0.55),
  ]);
  const TUBULAR = 40;
  const RADIAL = 12;
  const geometry = new THREE.TubeGeometry(curve, TUBULAR, 0.17, RADIAL, false);
  const pos = geometry.attributes.position as THREE.BufferAttribute;
  const center = new THREE.Vector3();
  // TubeGeometry places ring i at path.getPointAt(i / tubularSegments) with radialSegments+1
  // vertices per ring, laid out ring-by-ring — so ring centers can be re-derived from the curve.
  for (let i = 0; i <= TUBULAR; i++) {
    const t = i / TUBULAR;
    curve.getPointAt(t, center);
    let f = 1 - 0.8 * Math.pow(t, 1.4);
    if (t > 0.8) f *= 0.9 + Math.random() * 0.2; // per-ring jitter → slightly ragged stump
    for (let j = 0; j <= RADIAL; j++) {
      const k = i * (RADIAL + 1) + j;
      pos.setXYZ(
        k,
        center.x + (pos.getX(k) - center.x) * f,
        center.y + (pos.getY(k) - center.y) * f,
        center.z + (pos.getZ(k) - center.z) * f
      );
    }
  }
  pos.needsUpdate = true;
  geometry.computeVertexNormals();
  return geometry;
}

export default function EyeOrb() {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [webglFailed, setWebglFailed] = useState(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      setWebglFailed(true);
      return;
    }
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(SIZE, SIZE);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    // Distance chosen so both the radius-1 ball and the tail clear the frustum. At FOV 35°/z=5.2
    // the frustum half-height is ~1.64 at the ball's equator and ~1.81 at the tail tip's depth
    // (z≈-0.55) — enough for the stalk to droop to y≈-1.45 and still swing with the gaze un-cropped
    // (together with TAIL_FOLLOW damping the swing; see that constant's comment).
    const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 12);
    camera.position.set(0, 0, 5.2);

    // three.js r155+ defaults to physically-correct light units, where the old "intensity ~1"
    // convention reads as quite dim — these are tuned up accordingly for a bright, non-gray sclera.
    scene.add(new THREE.AmbientLight(0xffffff, 1.4));
    const key = new THREE.DirectionalLight(0xffffff, 3.2);
    key.position.set(-1.2, 1.5, 2);
    scene.add(key);
    // A soft fill from the opposite side keeps the shaded side of the sphere from going muddy and
    // gives the glossy cornea a second, subtler glint.
    const fill = new THREE.DirectionalLight(0xffe6f2, 0.9);
    fill.position.set(1.6, -0.6, 1.2);
    scene.add(fill);

    const scleraTexture = makeScleraTexture();
    const scleraGeometry = new THREE.SphereGeometry(1, 64, 64);
    // Default SphereGeometry UVs put the texture's horizontal center (u=0.5) on +X — the right
    // side of the ball from the camera — which made the vein convergence and bloom read as coming
    // from the right and creeping left. Rotating the geometry brings u=0.5 around to +Z (the
    // camera/iris side), so vessels now originate at the back and grow forward toward the limbus.
    // Bonus: the UV seam (canvas left/right edges) moves to the back, hidden behind the ball by
    // the tail. The pulse shell below gets the same re-aim so both layers stay registered.
    scleraGeometry.rotateY(-Math.PI / 2);
    const scleraMaterial = new THREE.MeshStandardMaterial({
      map: scleraTexture,
      roughness: 0.28,
      metalness: 0,
    });
    const sclera = new THREE.Mesh(scleraGeometry, scleraMaterial);

    // Throbbing redness: bloom + trunk vessels on a shell a hair outside the sclera, opacity
    // animated on a heartbeat in the render loop. depthWrite off so it blends over the sclera
    // without fighting it; the opaque iris/pupil discs sit outside this radius and depth-occlude it.
    const pulseTexture = makePulseTexture();
    const pulseGeometry = new THREE.SphereGeometry(1.002, 64, 64);
    pulseGeometry.rotateY(-Math.PI / 2); // same UV re-aim as the sclera — keeps the layers registered
    const pulseMaterial = new THREE.MeshStandardMaterial({
      map: pulseTexture,
      transparent: true,
      opacity: 0.9,
      depthWrite: false,
      roughness: 0.28,
      metalness: 0,
    });
    const pulseShell = new THREE.Mesh(pulseGeometry, pulseMaterial);

    const irisTexture = makeIrisTexture();
    const irisGeometry = new THREE.CircleGeometry(0.42, 48);
    const irisMaterial = new THREE.MeshStandardMaterial({
      map: irisTexture,
      roughness: 0.42,
      metalness: 0,
    });
    // The sclera sphere has radius 1, so anything meant to sit "on" its front surface must stay
    // outside that radius or the sphere's own curved shell occludes it. Offsetting the iris/pupil/
    // cornea *meshes* (not the group) past z=1 and rotating the *group* around the origin — rather
    // than offsetting the group and rotating it around its own off-center position — means every
    // point on those meshes keeps a world-space distance from the origin of at least its offset,
    // regardless of rotation angle (distance from the rotation center is rotation-invariant), so
    // nothing ever dips back inside the sclera at any gaze angle within the clamp.
    const iris = new THREE.Mesh(irisGeometry, irisMaterial);
    iris.position.z = 1.02;

    const pupilGeometry = new THREE.CircleGeometry(0.15, 48);
    const pupilMaterial = new THREE.MeshBasicMaterial({ color: 0x050505 });
    const pupil = new THREE.Mesh(pupilGeometry, pupilMaterial);
    pupil.position.z = 1.035;

    // Corneal bulge: a clear, glassy spherical cap doming over the iris — the biggest missing 3D
    // cue. We use MeshPhysicalMaterial with a strong clearcoat specular lobe + very low base opacity
    // (rather than true `transmission`) on purpose: transmission needs an extra opaque render pass
    // into a render target, which is fragile against this canvas's transparent (alpha) background —
    // clearcoat gives the same wet-glass bulge/highlight/depth read while rendering reliably over a
    // transparent clear color. ior 1.376 is the real cornea's index of refraction (drives the
    // Fresnel edge brightening). The cap is built around three's +Y pole then rotated to face +Z.
    const CORNEA_R = 0.85;
    const corneaGeometry = new THREE.SphereGeometry(CORNEA_R, 48, 32, 0, Math.PI * 2, 0, 0.63);
    corneaGeometry.rotateX(Math.PI / 2); // point the cap toward +Z (the viewer / iris)
    const corneaMaterial = new THREE.MeshPhysicalMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.16,
      roughness: 0.05,
      metalness: 0,
      clearcoat: 1,
      clearcoatRoughness: 0.04,
      ior: 1.376,
      reflectivity: 0.6,
      depthWrite: false,
      side: THREE.FrontSide,
    });
    const cornea = new THREE.Mesh(corneaGeometry, corneaMaterial);
    cornea.position.z = 0.332; // apex ends up at ~1.18, rim (r~0.5) sits just past the iris edge
    cornea.renderOrder = 1; // draw the transparent dome after the opaque iris/pupil beneath it

    // The whole ball rotates as one — sclera included — so the vein texture (and the tail behind
    // it) follows the gaze instead of the iris sliding over a frozen sphere.
    const eyeGroup = new THREE.Group();
    eyeGroup.add(sclera, pulseShell, iris, pupil, cornea);
    scene.add(eyeGroup);

    // The tail pivots at the origin like the eye but is NOT parented to eyeGroup: its rotation
    // chases the eye's at a slower ease in the render loop, so it drags behind gaze changes and
    // sways on its own — secondary motion without bones or physics.
    const tailTexture = makeNerveTexture();
    const tailGeometry = makeTailGeometry();
    const tailMaterial = new THREE.MeshStandardMaterial({
      map: tailTexture,
      roughness: 0.45,
      metalness: 0,
    });
    const tail = new THREE.Mesh(tailGeometry, tailMaterial);
    const tailGroup = new THREE.Group();
    tailGroup.add(tail);
    scene.add(tailGroup);

    // Native listener + plain locals (not React state) so mousemove never triggers a re-render.
    const mouseTarget = { x: 0, y: 0 };
    let lastMouseMove = performance.now();
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      mouseTarget.x = e.clientX - cx;
      mouseTarget.y = e.clientY - cy;
      lastMouseMove = performance.now();
    };
    window.addEventListener("mousemove", onMouseMove);

    // Gaze-controller state (see the dynamics list in the header comment).
    const gaze = { x: 0, y: 0 };
    const wander = { x: 0, y: 0 };
    const micro = { x: 0, y: 0 };
    let ease = SETTLE_EASE;
    let nextWander = 0;
    let nextMicro = 0;
    let pupilScale = 1;
    let tailSwayX = 0;

    function animate() {
      const now = performance.now();

      // Base gaze target: the cursor while it's active, otherwise idle wandering — the eye "looks
      // around" on its own after IDLE_MS without mouse movement, snapping back on the next move.
      let baseRotX: number;
      let baseRotY: number;
      if (now - lastMouseMove < IDLE_MS) {
        baseRotY = THREE.MathUtils.clamp(mouseTarget.x / NORMALIZE_PX, -1, 1) * MAX_DEFLECTION;
        // No negation here: three.js's rotation.x already maps a positive angle to "look down" (a
        // point on +Z rotates toward -Y under positive rotation.x), so a positive angle for a cursor
        // that's below center (mouseTarget.y > 0, since browser Y grows downward) is what's wanted.
        // An earlier version negated this and the eye tracked vertically backwards as a result.
        baseRotX = THREE.MathUtils.clamp(mouseTarget.y / NORMALIZE_PX, -1, 1) * MAX_DEFLECTION;
      } else {
        if (now >= nextWander) {
          wander.x = (Math.random() * 2 - 1) * MAX_DEFLECTION * 0.75;
          wander.y = (Math.random() * 2 - 1) * MAX_DEFLECTION * 0.75;
          nextWander = now + 1500 + Math.random() * 2500;
        }
        baseRotX = wander.x;
        baseRotY = wander.y;
      }

      // Micro-saccades: tiny random fixation offsets, corrected by the next one — constant life.
      if (now >= nextMicro) {
        micro.x = (Math.random() - 0.5) * THREE.MathUtils.degToRad(2.4);
        micro.y = (Math.random() - 0.5) * THREE.MathUtils.degToRad(2.4);
        nextMicro = now + 600 + Math.random() * 1900;
      }
      const targetRotX = THREE.MathUtils.clamp(baseRotX + micro.x, -MAX_DEFLECTION, MAX_DEFLECTION);
      const targetRotY = THREE.MathUtils.clamp(baseRotY + micro.y, -MAX_DEFLECTION, MAX_DEFLECTION);

      // Two-speed ease: a big target jump triggers the fast saccade snap, which sticks until the
      // eye is nearly on target, then drops back to the slow fixation settle.
      const err = Math.hypot(targetRotX - gaze.x, targetRotY - gaze.y);
      if (err > SACCADE_START) ease = SACCADE_EASE;
      else if (err < SACCADE_END) ease = SETTLE_EASE;
      gaze.x = THREE.MathUtils.lerp(gaze.x, targetRotX, ease);
      gaze.y = THREE.MathUtils.lerp(gaze.y, targetRotY, ease);
      eyeGroup.rotation.x = gaze.x;
      eyeGroup.rotation.y = gaze.y;

      // Fake iris-recess parallax: a real iris sits ~3mm behind the cornea, so it visibly lags
      // inside the glassy dome when the eye turns. Shifting the discs against the gaze reads the
      // same at this render size. Signs: positive rotation.y swings the front toward +X, so a
      // deeper point lags toward -X; positive rotation.x looks down (+Z toward -Y), so a deeper
      // point lags upward (+Y). Lateral shifts only grow the discs' distance from the origin
      // (z stays 1.02/1.035), so the sclera-never-occludes invariant above still holds.
      const recessX = -Math.sin(gaze.y) * IRIS_RECESS;
      const recessY = Math.sin(gaze.x) * IRIS_RECESS;
      iris.position.x = recessX;
      iris.position.y = recessY;
      pupil.position.x = recessX;
      pupil.position.y = recessY;

      // Tail lag + idle dangle. The sway terms are added on top of the chased base rotation each
      // frame (rather than baked into it) so they don't fight the lerp.
      tailGroup.rotation.x = THREE.MathUtils.lerp(tailGroup.rotation.x - tailSwayX, gaze.x * TAIL_FOLLOW, TAIL_EASE);
      tailGroup.rotation.y = THREE.MathUtils.lerp(tailGroup.rotation.y, gaze.y * TAIL_FOLLOW, TAIL_EASE);
      tailSwayX = Math.sin(now * 0.0011) * 0.05;
      tailGroup.rotation.x += tailSwayX;
      tailGroup.rotation.z = Math.sin(now * 0.0007) * 0.06 + Math.sin(now * 0.0013) * 0.03;

      // Pupil: slow hippus oscillation (two incommensurate sines) modulated by cursor proximity —
      // constricts as the cursor closes in, dilates when it's far — with a sluggish lerp so the
      // response feels muscular, not instant.
      const cursorDist = Math.hypot(mouseTarget.x, mouseTarget.y);
      const near = THREE.MathUtils.clamp(1 - cursorDist / 520, 0, 1);
      const hippus = 1 + 0.08 * (Math.sin(now * 0.00042) * 0.6 + Math.sin(now * 0.00097 + 1.7) * 0.4);
      const targetScale = THREE.MathUtils.lerp(1.25, 0.75, near) * hippus;
      pupilScale = THREE.MathUtils.lerp(pupilScale, targetScale, 0.05);
      pupil.scale.set(pupilScale, pupilScale, 1);

      // Vein pulse: sharp-attack/slow-decay beat at ~55bpm — reads as throbbing irritation, not a
      // sine strobe.
      const p = (now % PULSE_MS) / PULSE_MS;
      const beat = p < 0.12 ? p / 0.12 : Math.pow(1 - (p - 0.12) / 0.88, 3);
      pulseMaterial.opacity = 0.55 + 0.35 * beat;

      renderer.render(scene, camera);
    }
    renderer.setAnimationLoop(animate);

    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      renderer.setAnimationLoop(null);
      scleraGeometry.dispose();
      scleraMaterial.dispose();
      scleraTexture.dispose();
      pulseGeometry.dispose();
      pulseMaterial.dispose();
      pulseTexture.dispose();
      irisGeometry.dispose();
      irisMaterial.dispose();
      irisTexture.dispose();
      pupilGeometry.dispose();
      pupilMaterial.dispose();
      corneaGeometry.dispose();
      corneaMaterial.dispose();
      tailGeometry.dispose();
      tailMaterial.dispose();
      tailTexture.dispose();
      renderer.dispose();
      container.removeChild(renderer.domElement);
    };
  }, []);

  if (webglFailed) {
    return <span className="eye-btn-icon">◉</span>;
  }
  return <div ref={containerRef} className="eye-orb" aria-hidden="true" />;
}
