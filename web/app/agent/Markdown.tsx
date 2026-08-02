"use client";
// Renders agent-authored markdown (thinking text, tool/subagent summaries) instead of dumping it as
// an inert pre-wrap blob. Security note, since this is a security tool: agent output regularly
// quotes back attacker-influenced strings straight from scan targets (banners, HTTP responses, repo
// contents, …), so this component deliberately does NOT enable raw HTML. `react-markdown` parses to
// a React element tree and never touches innerHTML by default; `rehype-raw` is the plugin that would
// opt back into rendering literal <script>/<img onerror>/etc nodes found in the markdown source, and
// it is intentionally not installed or imported here. Losing the rare legitimate inline-HTML snippet
// is a trivial trade for never executing markup sourced from a target the operator doesn't control.
import ReactMarkdown from "react-markdown";

export default function Markdown({ text }: { text: string }) {
  if (!text) return null;
  return (
    <div className="md">
      <ReactMarkdown
        components={{
          // External links (findings often cite CVE/vendor URLs) open in a new tab rather than
          // navigating the operator away from a live run.
          a: ({ children, href }) => (
            <a href={href} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
          // A bare <table> doesn't scroll on its own — wrap it so a wide table scrolls inside its
          // own box instead of forcing the whole chat sideways (the chat itself must never scroll
          // horizontally; see .md-table-wrap / .md pre in globals.css for the matching overflow rules).
          table: ({ children }) => (
            <div className="md-table-wrap">
              <table>{children}</table>
            </div>
          ),
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
