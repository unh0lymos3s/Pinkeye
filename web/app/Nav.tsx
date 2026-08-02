"use client";
// Floating nav: collapsed to a small tab on the right edge, expands into a link list on hover
// (or focus, for keyboard use) so it never occupies permanent screen space or carries a masthead.
//
// Also the one place the operator manages their API key: the control plane now requires at least a
// `viewer` X-API-Key on every route (open dev mode — no EYE_API_KEYS on the server — needs no key at
// all, so this stays entirely optional). The key lives in sessionStorage, entered here, and every
// call in lib/api.ts picks it up automatically.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  API_BASE,
  AUTH_NOTICE_EVENT,
  clearApiKey,
  getApiKey,
  setApiKey,
  type AuthNotice,
} from "../lib/api";

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
  const [hasKey, setHasKey] = useState(false);
  const [draft, setDraft] = useState("");
  const [notice, setNotice] = useState<AuthNotice | null>(null);

  // Read on mount only (client-side; sessionStorage isn't available during SSR).
  useEffect(() => {
    setHasKey(!!getApiKey());
  }, []);

  // Any 401/403 anywhere in the app surfaces here, so the operator doesn't need to go hunting for
  // which page's fetch silently failed.
  useEffect(() => {
    const onNotice = (e: Event) => setNotice((e as CustomEvent<AuthNotice>).detail);
    window.addEventListener(AUTH_NOTICE_EVENT, onNotice);
    return () => window.removeEventListener(AUTH_NOTICE_EVENT, onNotice);
  }, []);

  function save() {
    const v = draft.trim();
    if (!v) return;
    setApiKey(v);
    setDraft(""); // never keep the typed value around once it's stored
    setHasKey(true);
    setNotice(null);
  }

  function clear() {
    clearApiKey();
    setHasKey(false);
  }

  // The product page (/product) is the public-facing page: no operator links, no API-key entry.
  // Hooks above run unconditionally so this early return doesn't change hook order between routes.
  if (path?.startsWith("/product")) return null;

  return (
    <nav className="nav-bubble">
      <div className="nav-bubble-panel">
        {notice && (
          <div className={`nav-auth-notice${notice.status === 403 ? " role" : ""}`}>{notice.message}</div>
        )}
        <div className="nav-key">
          <span className="dim" style={{ fontSize: 11 }}>
            {hasKey ? "API key set" : "No API key set"}
          </span>
          {hasKey ? (
            <button type="button" className="mini-btn" onClick={clear}>
              Clear key
            </button>
          ) : (
            <div className="nav-key-row">
              <input
                type="password"
                autoComplete="off"
                className="input nav-key-input"
                placeholder="X-API-Key"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") save();
                }}
              />
              <button type="button" className="mini-btn" onClick={save} disabled={!draft.trim()}>
                Save
              </button>
            </div>
          )}
        </div>
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
      <div className="nav-bubble-tab" aria-hidden="true">
        ◉{notice && <span className="nav-auth-dot" />}
      </div>
    </nav>
  );
}
