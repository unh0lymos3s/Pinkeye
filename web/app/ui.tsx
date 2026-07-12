// Small set of shared presentational components used across pages. Keeping these here
// means the pages stay declarative and every screen renders severities, cards, and
// empty states the same way.
import type { ReactNode } from "react";

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
export const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "info").toLowerCase();
  const cls = SEV_ORDER.includes(s as any) ? s : "info";
  return (
    <span className={`badge sev-${cls}`}>
      <span className="dot" />
      {severity || "info"}
    </span>
  );
}

export function Kpi({ label, value, accent, hint }: { label: string; value: ReactNode; accent?: string; hint?: string }) {
  return (
    <div className="kpi" style={accent ? ({ ["--accent" as any]: accent }) : undefined}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="section-title">
      <h3>{children}</h3>
      <div className="rule" />
      {action}
    </div>
  );
}

export function Callout({ kind = "info", icon, children }: { kind?: "info" | "warn" | "danger"; icon?: string; children: ReactNode }) {
  const cls = kind === "warn" ? "callout-warn" : kind === "danger" ? "callout-danger" : "";
  const defaultIcon = kind === "danger" ? "⛔" : kind === "warn" ? "⚠" : "ⓘ";
  return (
    <div className={`callout ${cls}`}>
      <span className="ico">{icon ?? defaultIcon}</span>
      <div>{children}</div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
