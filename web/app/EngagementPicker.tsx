"use client";
// Dropdown to pick the active engagement; shared by the dashboard, query, and map pages.
import type { Engagement } from "../lib/api";

export default function EngagementPicker({
  engagements,
  selected,
  onSelect,
}: {
  engagements: Engagement[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  return (
    <select className="select" value={selected} onChange={(e) => onSelect(e.target.value)} aria-label="Active engagement">
      <option value="">— select engagement —</option>
      {engagements.map((e) => (
        <option key={e.id} value={e.id}>
          {e.name}
        </option>
      ))}
    </select>
  );
}
