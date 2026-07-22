"use client";
// Top navigation shared across pages. Links the map, dashboard, query, and guide views.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { API_BASE } from "../lib/api";

const LINKS = [
  { href: "/", label: "Network Map" },
  { href: "/agent", label: "Agent Chat" },
  { href: "/sast", label: "SAST" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/query", label: "Query" },
  { href: "/guide", label: "Guide" },
];

export default function Nav() {
  const path = usePathname();
  return (
    <nav className="nav">
      <Link href="/" className="brand" style={{ textDecoration: "none", color: "var(--text)" }}>
        <span className="eye">◉</span>
        <span className="name">Codename Eye</span>
      </Link>
      {LINKS.map((l) => {
        const active = l.href === "/" ? path === "/" : path.startsWith(l.href);
        return (
          <Link key={l.href} href={l.href} className={`nav-link${active ? " active" : ""}`}>
            {l.label}
          </Link>
        );
      })}
      <span className="spacer" />
      <a
        className="nav-link"
        href={`${API_BASE}/docs`}
        target="_blank"
        rel="noreferrer"
        title="Interactive OpenAPI docs"
      >
        API ↗
      </a>
    </nav>
  );
}
