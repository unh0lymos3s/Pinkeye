"use client";
// Compact session switcher (chat-UI contract, "chat sessions" ask). Sessions are a browser-local
// concept layered on top of server-persisted run transcripts (see web/lib/sessions.ts) — the control
// plane only knows about runs. This lives in the topbar rather than inside the gear panel: unlike run
// configuration (set once before launching, rarely revisited), switching or naming a conversation is
// something an operator reaches for constantly while chatting, so it needs to be one click away
// without opening the control panel — and keeping it out of the transcript itself is what lets the
// chat stay the single clean box the redesign also asks for.
import { useEffect, useRef, useState } from "react";
import type { Session } from "../../lib/sessions";

export default function SessionSwitcher({
  sessions,
  activeId,
  onSelect,
  onCreate,
  onRename,
  onDelete,
}: {
  sessions: Session[];
  activeId: string;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (id: string, title: string) => void;
  onDelete: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement | null>(null);

  // Close (and drop any in-progress rename/delete-confirm) on outside click or Esc — the same pattern
  // ControlPanel/ToolLibrary already use for their own popovers.
  useEffect(() => {
    if (!open) return;
    const reset = () => {
      setOpen(false);
      setEditingId(null);
      setConfirmingId(null);
    };
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) reset();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") reset();
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const active = sessions.find((s) => s.id === activeId);
  const label = active?.title || "New session";

  function startRename(s: Session) {
    setEditingId(s.id);
    setDraft(s.title);
    setConfirmingId(null);
  }
  function commitRename(id: string) {
    const t = draft.trim();
    if (t) onRename(id, t);
    setEditingId(null);
  }

  return (
    <div className="session-switcher" ref={ref}>
      <button
        type="button"
        className="session-trigger"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label="Chat sessions"
      >
        <span>{label}</span>
        <span className="dim" aria-hidden>
          ▾
        </span>
      </button>
      {open && (
        <div className="session-menu">
          <div className="session-menu-head">
            <span className="dim">Sessions</span>
            <button
              type="button"
              className="mini-btn"
              onClick={() => {
                onCreate();
                setOpen(false);
              }}
            >
              + New
            </button>
          </div>
          <div className="session-menu-body">
            {sessions.length === 0 && <div className="dim session-empty">No sessions yet.</div>}
            {sessions.map((s) => (
              <div key={s.id} className={`session-row${s.id === activeId ? " active" : ""}`}>
                {editingId === s.id ? (
                  <input
                    className="input session-rename-input"
                    autoFocus
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitRename(s.id);
                      if (e.key === "Escape") setEditingId(null);
                    }}
                    onBlur={() => commitRename(s.id)}
                  />
                ) : (
                  <button
                    type="button"
                    className="session-row-title"
                    onClick={() => {
                      onSelect(s.id);
                      setOpen(false);
                    }}
                    title={s.runId ? `run ${s.runId.slice(0, 8)}` : "no run launched yet"}
                  >
                    {s.title}
                  </button>
                )}
                {editingId !== s.id &&
                  (confirmingId === s.id ? (
                    <span className="session-row-actions">
                      {/* Deleting only forgets this browser's pointer — the run (if any) is still on
                          the server and unaffected. Say so inline rather than a native confirm(),
                          which this app avoids in favor of in-flow buttons (see Approve/Deny above). */}
                      <span className="dim">forget it? (server data stays)</span>
                      <button
                        type="button"
                        className="mini-btn"
                        onClick={() => {
                          onDelete(s.id);
                          setConfirmingId(null);
                        }}
                      >
                        Yes
                      </button>
                      <button type="button" className="mini-btn" onClick={() => setConfirmingId(null)}>
                        No
                      </button>
                    </span>
                  ) : (
                    <span className="session-row-actions">
                      <button type="button" className="mini-btn" onClick={() => startRename(s)}>
                        Rename
                      </button>
                      <button type="button" className="mini-btn" onClick={() => setConfirmingId(s.id)}>
                        Delete
                      </button>
                    </span>
                  ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
