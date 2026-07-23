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
