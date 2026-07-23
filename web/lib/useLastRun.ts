"use client";
// Shared "most recent run" per engagement, persisted in localStorage so it survives navigation
// from the landing page (where a run is launched) to the map page (where its Changes panel lives).
import { useEffect, useState } from "react";

const KEY_PREFIX = "eye.lastRunId.";

export function useLastRun(engagementId: string) {
  const [lastRunId, setLastRunIdState] = useState<string>("");

  useEffect(() => {
    if (typeof window === "undefined" || !engagementId) {
      setLastRunIdState("");
      return;
    }
    setLastRunIdState(localStorage.getItem(KEY_PREFIX + engagementId) || "");
  }, [engagementId]);

  function setLastRunId(runId: string) {
    setLastRunIdState(runId);
    if (typeof window !== "undefined" && engagementId) {
      localStorage.setItem(KEY_PREFIX + engagementId, runId);
    }
  }

  return { lastRunId, setLastRunId };
}
