// Public product page — the outward-facing face of Pinkeye, as opposed to the operator launcher at
// `/`. Deliberately inert: it shares the landing page's wordmark and eye orb but carries none of its
// controls (no engagement picker, no run launcher, no map/graph link) and the floating nav hides
// itself here (see Nav.tsx), so nothing on this page can reach the control plane. That means it
// stays safe to expose publicly even when the operator UI behind it is not.
import type { Metadata } from "next";
import AsciiBanner from "../AsciiBanner";
import EyeOrb from "../EyeOrb";

const GITHUB_URL = "https://github.com/unh0lymos3s/Pinkeye";

export const metadata: Metadata = {
  title: "Pinkeye — Cyber kill chain harness",
  description: "Cyber kill chain harness coming soon.",
};

export default function Product() {
  return (
    <main className="launcher product">
      <AsciiBanner />

      {/* Same 160px footprint as the launcher's .eye-btn so the orb overflows it identically — but
          a plain div, not a Link: here the eye is the product's mascot, not a control. */}
      <div className="eye-mount">
        <EyeOrb />
      </div>

      <p className="product-tagline">Cyber kill chain harness coming soon</p>

      <a className="btn btn-primary product-cta" href={GITHUB_URL} target="_blank" rel="noreferrer">
        View the GitHub repo ↗
      </a>
    </main>
  );
}
