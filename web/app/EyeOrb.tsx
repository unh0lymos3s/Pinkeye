"use client";
// A real 3D eyeball (not a flat icon) that tracks the cursor — the one deliberate departure from
// the rest of the app's flat, shadow-free "shocking pink + white" design system. Floats freely on
// the page (no boxed-in background — see globals.css .eye-btn/.eye-orb) so it reads as a perfectly
// round orb rather than an icon inside a square card. Bare orb only: no eyelid, no glare/highlight.
//
// Scene graph:
//   scene
//   ├─ ambient + directional key + soft fill light
//   ├─ sclera (static sphere, bloodshot/infected "pink eye" texture — the app's own namesake)
//   └─ irisGroup (rotates to track the cursor)
//      ├─ iris (flat disc, radial-fiber + limbal-ring texture, brand pink)
//      ├─ pupil (flat black disc)
//      └─ cornea (clear bulged dome — MeshPhysicalMaterial clearcoat — sells the eye as 3D)
import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

// Rendered larger than the 190px click target so the orb overflows it, staying round. Bumped from
// 224 to 250 to compensate for the camera being pulled back (see camera.position.z below) to fix
// side-cropping — a longer camera distance means the sphere fills less of the frame, so the canvas
// needs to grow a bit to keep the eye's on-screen size close to what it was before that fix.
const SIZE = 250;
const MAX_DEFLECTION = THREE.MathUtils.degToRad(28); // clamp so the iris never turns past the front hemisphere
const EASE = 0.11; // lerp factor: eye "settles" onto the cursor instead of snapping
const NORMALIZE_PX = 460; // cursor distance (px) at which the eye is already at max deflection

// Draws the sclera's texture: an infected, bloodshot "pink eye" (conjunctivitis) look — the app's
// own namesake condition. A warm reddened wash concentrated toward the iris (real conjunctivitis
// presents as redness radiating in from the edges toward the cornea — "ciliary injection"), a few
// thick engorged vessels reaching toward the center, plus a dense field of fine red capillaries.
function makeScleraTexture(): THREE.CanvasTexture {
  const size = 1024;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;

  // SphereGeometry's default UV wrap puts the visible front (where the iris sits) near the texture's
  // center, and the top/bottom poles at the vertical edges. Keep the base itself close to true white
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
  // A strong red bloom over the front, near the iris — the hallmark of conjunctivitis is redness
  // that's worst right at the limbus and fades outward. Pushed well past "warm tint" into visibly
  // red, since strong scene lighting (needed to keep the rest of the sclera bright white) otherwise
  // washes out anything subtler.
  const bloom = ctx.createRadialGradient(size / 2, size / 2, size * 0.02, size / 2, size / 2, size * 0.48);
  bloom.addColorStop(0, "rgba(215, 15, 30, 0.75)");
  bloom.addColorStop(0.45, "rgba(220, 30, 40, 0.4)");
  bloom.addColorStop(0.8, "rgba(220, 40, 50, 0.12)");
  bloom.addColorStop(1, "rgba(220, 40, 50, 0)");
  ctx.fillStyle = bloom;
  ctx.fillRect(0, 0, size, size);

  // A handful of thick, engorged vessels radiating from near the iris edge outward — "ciliary
  // injection," the vessel pattern that actually reads as an infected/irritated eye rather than just
  // scattered noise. Drawn first so the finer capillary web layers on top of them.
  const majorVeinCount = 20;
  for (let i = 0; i < majorVeinCount; i++) {
    const angle = Math.random() * Math.PI * 2;
    const startR = size * (0.1 + Math.random() * 0.06);
    const endR = size * (0.34 + Math.random() * 0.22);
    const sx = size / 2 + Math.cos(angle) * startR;
    const sy = size / 2 + Math.sin(angle) * startR;
    const wobble = angle + (Math.random() - 0.5) * 0.5;
    const ex = size / 2 + Math.cos(wobble) * endR;
    const ey = size / 2 + Math.sin(wobble) * endR;
    const mx = (sx + ex) / 2 + (Math.random() - 0.5) * size * 0.05;
    const my = (sy + ey) / 2 + (Math.random() - 0.5) * size * 0.05;
    ctx.strokeStyle = `rgba(200, 8, 20, ${0.6 + Math.random() * 0.35})`;
    ctx.lineWidth = 2 + Math.random() * 2.8;
    ctx.lineCap = "round";
    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.quadraticCurveTo(mx, my, ex, ey);
    ctx.stroke();
  }

  // Dense fine capillary web: a branching red vein is more convincing than a single stroke, so each
  // root spawns a main curve plus a couple of thinner offshoots. Unlike a healthy eye, density and
  // alpha stay high right up to the iris edge instead of fading out near the center.
  const veinCount = 220;
  for (let i = 0; i < veinCount; i++) {
    const band = Math.random() < 0.5 ? -1 : 1;
    let sy = size / 2 + band * (size * 0.03 + Math.random() * size * 0.44);
    let sx = Math.random() * size;
    const baseAlpha = 0.32 + Math.random() * 0.45;
    const branches = 1 + (Math.random() < 0.65 ? 1 : 0) + (Math.random() < 0.35 ? 1 : 0);
    for (let b = 0; b < branches; b++) {
      const angle = Math.random() * Math.PI * 2;
      const len = size * (0.025 + Math.random() * 0.12);
      const ex = sx + Math.cos(angle) * len;
      const ey = sy + Math.sin(angle) * len;
      const mx = (sx + ex) / 2 + (Math.random() - 0.5) * len * 0.7;
      const my = (sy + ey) / 2 + (Math.random() - 0.5) * len * 0.7;
      const a = baseAlpha * (b === 0 ? 1 : 0.65);
      const deep = Math.random() > 0.4;
      ctx.strokeStyle = deep
        ? `rgba(185, 5, 20, ${a})`
        : `rgba(225, 35, 50, ${a})`;
      ctx.lineWidth = (b === 0 ? 0.9 : 0.5) + Math.random() * (b === 0 ? 1.6 : 0.8);
      ctx.lineCap = "round";
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.quadraticCurveTo(mx, my, ex, ey);
      ctx.stroke();
      // walk the branch root outward so offshoots trail off the main line
      sx = mx;
      sy = my;
    }
  }

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
    // Distance chosen so the radius-1 sclera comfortably clears the frustum on every side: at
    // FOV 35°/distance 3.2 the frustum's half-width at the sphere's equator was ~1.009 — almost
    // exactly the sphere's own radius, so it was clipped flat at the left/right edges. At 4.0 the
    // half-width is ~1.26, leaving ~20% margin all around instead of ~1%.
    const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 10);
    camera.position.set(0, 0, 4.0);

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
    const scleraMaterial = new THREE.MeshStandardMaterial({
      map: scleraTexture,
      roughness: 0.28,
      metalness: 0,
    });
    const sclera = new THREE.Mesh(scleraGeometry, scleraMaterial);
    scene.add(sclera);

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

    const irisGroup = new THREE.Group();
    irisGroup.add(iris, pupil, cornea);
    scene.add(irisGroup);

    // Native listener + a plain ref (not React state) so mousemove never triggers a re-render.
    const mouseTarget = { x: 0, y: 0 };
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      mouseTarget.x = e.clientX - cx;
      mouseTarget.y = e.clientY - cy;
    };
    window.addEventListener("mousemove", onMouseMove);

    function animate() {
      const targetRotY = THREE.MathUtils.clamp(mouseTarget.x / NORMALIZE_PX, -1, 1) * MAX_DEFLECTION;
      // No negation here: three.js's rotation.x already maps a positive angle to "look down" (a
      // point on +Z rotates toward -Y under positive rotation.x), so a positive angle for a cursor
      // that's below center (mouseTarget.y > 0, since browser Y grows downward) is what's wanted.
      // An earlier version negated this and the eye tracked vertically backwards as a result.
      const targetRotX = THREE.MathUtils.clamp(mouseTarget.y / NORMALIZE_PX, -1, 1) * MAX_DEFLECTION;
      irisGroup.rotation.y = THREE.MathUtils.lerp(irisGroup.rotation.y, targetRotY, EASE);
      irisGroup.rotation.x = THREE.MathUtils.lerp(irisGroup.rotation.x, targetRotX, EASE);
      renderer.render(scene, camera);
    }
    renderer.setAnimationLoop(animate);

    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      renderer.setAnimationLoop(null);
      scleraGeometry.dispose();
      scleraMaterial.dispose();
      scleraTexture.dispose();
      irisGeometry.dispose();
      irisMaterial.dispose();
      irisTexture.dispose();
      pupilGeometry.dispose();
      pupilMaterial.dispose();
      corneaGeometry.dispose();
      corneaMaterial.dispose();
      renderer.dispose();
      container.removeChild(renderer.domElement);
    };
  }, []);

  if (webglFailed) {
    return <span className="eye-btn-icon">◉</span>;
  }
  return <div ref={containerRef} className="eye-orb" aria-hidden="true" />;
}
