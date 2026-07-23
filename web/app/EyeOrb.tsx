"use client";
// A real 3D eyeball (not a flat icon) that tracks the cursor — the one deliberate departure from
// the rest of the app's flat, shadow-free "shocking pink + white" design system. Sits inside "The
// eye" landing button in place of the plain glyph. Bare orb only: no eyelid, no socket.
//
// Scene graph:
//   scene
//   ├─ ambient + directional light
//   ├─ sclera (static sphere, procedurally veined texture)
//   ├─ highlight (static "wet" catchlight dot)
//   └─ irisGroup (rotates to track the cursor)
//      ├─ iris (flat disc, radial fiber texture, brand pink)
//      └─ pupil (flat black disc)
import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

const SIZE = 132;
const MAX_DEFLECTION = THREE.MathUtils.degToRad(28); // clamp so the iris never turns past the front hemisphere
const EASE = 0.12; // lerp factor: eye "settles" onto the cursor instead of snapping
const NORMALIZE_PX = 420; // cursor distance (px) at which the eye is already at max deflection

// Draws the sclera's vein texture. Veins cluster near the equator (SphereGeometry's default UV
// wrap puts the visible front — where the iris sits — near the texture's vertical center too, so
// they're kept sparser there to avoid competing with the iris) and thin out toward the poles.
function makeScleraTexture(): THREE.CanvasTexture {
  const size = 512;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;

  ctx.fillStyle = "#fbf3f1";
  ctx.fillRect(0, 0, size, size);

  const veinCount = 55;
  for (let i = 0; i < veinCount; i++) {
    // Bias vertically toward the equator band; keep clear of the very center where the iris sits.
    const band = Math.random() < 0.5 ? -1 : 1;
    const sy = size / 2 + band * (size * 0.08 + Math.random() * size * 0.32);
    const sx = Math.random() * size;
    const angle = Math.random() * Math.PI * 2;
    const len = size * (0.05 + Math.random() * 0.16);
    const ex = sx + Math.cos(angle) * len;
    const ey = sy + Math.sin(angle) * len;
    const mx = (sx + ex) / 2 + (Math.random() - 0.5) * len * 0.6;
    const my = (sy + ey) / 2 + (Math.random() - 0.5) * len * 0.6;

    const warm = Math.random() > 0.5;
    const alpha = 0.15 + Math.random() * 0.3;
    ctx.strokeStyle = warm
      ? `rgba(230, 60, 90, ${alpha})`
      : `rgba(255, 130, 150, ${alpha})`;
    ctx.lineWidth = 0.4 + Math.random() * 1.2;
    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.quadraticCurveTo(mx, my, ex, ey);
    ctx.stroke();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.needsUpdate = true;
  return texture;
}

// Draws the iris's radial fiber texture: a dark-to-brand-pink gradient plus thin radial fibers.
function makeIrisTexture(): THREE.CanvasTexture {
  const size = 256;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2;

  const gradient = ctx.createRadialGradient(cx, cy, r * 0.08, cx, cy, r);
  gradient.addColorStop(0, "#c21a76");
  gradient.addColorStop(1, "#ff2da0");
  ctx.fillStyle = gradient;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  const fiberCount = 110;
  for (let i = 0; i < fiberCount; i++) {
    const angle = (i / fiberCount) * Math.PI * 2 + (Math.random() - 0.5) * 0.15;
    const inner = r * (0.15 + Math.random() * 0.1);
    const outer = r * (0.75 + Math.random() * 0.22);
    ctx.strokeStyle = `rgba(20, 4, 14, ${0.08 + Math.random() * 0.14})`;
    ctx.lineWidth = 0.6 + Math.random() * 0.8;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(angle) * inner, cy + Math.sin(angle) * inner);
    ctx.lineTo(cx + Math.cos(angle) * outer, cy + Math.sin(angle) * outer);
    ctx.stroke();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
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
    const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 10);
    camera.position.set(0, 0, 3.2);

    // three.js r155+ defaults to physically-correct light units, where the old "intensity ~1"
    // convention reads as quite dim — these are tuned up accordingly for a bright, non-gray sclera.
    scene.add(new THREE.AmbientLight(0xffffff, 1.4));
    const key = new THREE.DirectionalLight(0xffffff, 3.2);
    key.position.set(-1.2, 1.5, 2);
    scene.add(key);

    const scleraTexture = makeScleraTexture();
    const scleraGeometry = new THREE.SphereGeometry(1, 48, 48);
    const scleraMaterial = new THREE.MeshStandardMaterial({
      map: scleraTexture,
      roughness: 0.35,
      metalness: 0,
    });
    const sclera = new THREE.Mesh(scleraGeometry, scleraMaterial);
    scene.add(sclera);

    const irisTexture = makeIrisTexture();
    const irisGeometry = new THREE.CircleGeometry(0.42, 32);
    const irisMaterial = new THREE.MeshStandardMaterial({
      map: irisTexture,
      roughness: 0.3,
      metalness: 0,
    });
    // The sclera sphere has radius 1, so anything meant to sit "on" its front surface must stay
    // outside that radius or the sphere's own curved shell occludes it. Offsetting the iris/pupil
    // *meshes* (not the group) past z=1 and rotating the *group* around the origin — rather than
    // offsetting the group and rotating it around its own off-center position — means every point
    // on the flat iris disc keeps a world-space distance from the origin of at least its z-offset,
    // regardless of rotation angle (distance from the rotation center is rotation-invariant), so it
    // never dips back inside the sclera at any gaze angle within the clamp.
    const iris = new THREE.Mesh(irisGeometry, irisMaterial);
    iris.position.z = 1.06;

    const pupilGeometry = new THREE.CircleGeometry(0.16, 32);
    const pupilMaterial = new THREE.MeshBasicMaterial({ color: 0x0a0a0a });
    const pupil = new THREE.Mesh(pupilGeometry, pupilMaterial);
    pupil.position.z = 1.08;

    const irisGroup = new THREE.Group();
    irisGroup.add(iris, pupil);
    scene.add(irisGroup);

    const highlightGeometry = new THREE.CircleGeometry(0.05, 16);
    const highlightMaterial = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.9,
    });
    const highlight = new THREE.Mesh(highlightGeometry, highlightMaterial);
    highlight.position.set(-0.1, 0.12, 1.07);
    scene.add(highlight);

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
      const targetRotX = THREE.MathUtils.clamp(-mouseTarget.y / NORMALIZE_PX, -1, 1) * MAX_DEFLECTION;
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
      highlightGeometry.dispose();
      highlightMaterial.dispose();
      renderer.dispose();
      container.removeChild(renderer.domElement);
    };
  }, []);

  if (webglFailed) {
    return <span className="eye-btn-icon">◉</span>;
  }
  return <div ref={containerRef} className="eye-orb" aria-hidden="true" />;
}
