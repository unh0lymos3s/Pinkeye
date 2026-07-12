"use client";
// Shared selected-engagement state, persisted in localStorage so it survives page navigation.
import { useEffect, useState } from "react";
import { listEngagements, type Engagement } from "./api";

const KEY = "eye.engagementId";

export function useEngagement() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selected, setSelected] = useState<string>("");

  useEffect(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem(KEY) || "" : "";
    setSelected(saved);
    listEngagements()
      .then((list) => {
        setEngagements(list);
        // Default to the first engagement if nothing valid is selected yet.
        if (!saved && list[0]) select(list[0].id);
      })
      .catch(() => {});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function select(id: string) {
    setSelected(id);
    if (typeof window !== "undefined") localStorage.setItem(KEY, id);
  }

  return { engagements, selected, select, refresh: () => listEngagements().then(setEngagements) };
}
