"use client";
// The vertical, collapsible pipeline rail for the chat-first Agent Chat workspace (see
// docs/superpowers/specs/2026-07-23-shocking-pink-cyberpunk-redesign-design.md and the U2 section of
// the shared chat-UI contract). Replaces the old horizontal pipeline card: same per-stage semantics
// and tool-usage readout, just laid out top-to-bottom in a left rail that can collapse to a narrow
// strip of dots. All state (which stage is current, which are gated/skipped, open/closed) is owned
// by the caller — this component is a pure function of its props.

export type PipelineRailProps = {
  stages: string[];
  gated: string[]; // stage names the scope withholds
  enabledStages: Set<string>; // stages with at least one enabled tool
  currentStage: string;
  currentIndex: number;
  stageIndex: (stage: string) => number;
  open: boolean;
  onToggle: () => void;
  toolsUsed: number;
  budgetMax: number;
};

export default function PipelineRail({
  stages,
  gated,
  enabledStages,
  currentStage,
  currentIndex,
  stageIndex,
  open,
  onToggle,
  toolsUsed,
  budgetMax,
}: PipelineRailProps) {
  const pct = budgetMax > 0 ? Math.min(100, (toolsUsed / budgetMax) * 100) : 0;

  return (
    <div className={`agent-rail${open ? "" : " collapsed"}`}>
      <button
        type="button"
        className="rail-toggle"
        onClick={onToggle}
        aria-label={open ? "Collapse pipeline rail" : "Expand pipeline rail"}
        aria-expanded={open}
      >
        <span aria-hidden>{open ? "‹" : "›"}</span>
      </button>

      <div className="rail-stages">
        {stages.map((stage) => {
          // Precedence, unchanged from the old horizontal rail: scope-gated (hard off) →
          // operator-skipped via the tool library → run progress → not yet reached.
          const cls = gated.includes(stage)
            ? "gated"
            : !enabledStages.has(stage)
            ? "skipped"
            : stage === currentStage
            ? "active"
            : stageIndex(stage) < currentIndex
            ? "done"
            : "";
          const title =
            cls === "gated"
              ? "Gated — the engagement scope does not grant this stage's flag"
              : cls === "skipped"
              ? "Off — no tools for this stage are enabled in the tool library"
              : undefined;
          return (
            <div key={stage} className={`rail-stage ${cls}`} title={title}>
              <span className="dot" aria-hidden />
              <span className="rail-stage-label">{stage}</span>
            </div>
          );
        })}
      </div>

      <div className="rail-progress" title={`${toolsUsed} of ${budgetMax} tool calls used`}>
        <div className="rail-progress-label">
          <span className="rail-progress-text">Tool usage</span>
          <span className="mono rail-progress-count">
            {toolsUsed}/{budgetMax}
          </span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${pct}%` }} />
        </div>
      </div>
    </div>
  );
}
