import type { StatusModel } from "../models";

export function formatEventName(event: string): string {
  const formatted = event.replaceAll("_", " ").replace(/\s+/gu, " ").trim();
  return formatted.length === 0 ? "workflow event" : formatted;
}

export function durationCopy(
  status: StatusModel,
  durationLabel: string | null,
): string {
  const recordedDuration = durationLabel?.trim();
  if (
    recordedDuration !== undefined &&
    recordedDuration.length > 0 &&
    normalizeCopy(recordedDuration) !== normalizeCopy(status.label)
  ) {
    return recordedDuration;
  }

  if (status.tone === "queued") {
    return "Not started";
  }
  if (status.tone === "running") {
    return "Duration in progress";
  }
  return "Duration not recorded";
}

export function startTimeCopy(status: StatusModel): string {
  return status.tone === "queued"
    ? "Waiting to start"
    : "Start time not recorded";
}

export function emptyJobsCopy(status: StatusModel): string {
  if (status.tone === "queued") {
    return "Jobs will appear when this workflow starts.";
  }
  if (status.tone === "running") {
    return "No jobs have been recorded yet.";
  }
  return "No jobs were recorded for this run.";
}

export function emptyArtifactsCopy(status: StatusModel): string {
  if (status.tone === "queued") {
    return "Artifacts will appear after this run starts.";
  }
  if (status.tone === "running") {
    return "No artifacts have been recorded yet.";
  }
  return "This run did not produce any artifacts.";
}

function normalizeCopy(value: string): string {
  return value.trim().toLowerCase();
}
