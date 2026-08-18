import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { JobLogPageModel } from "../models";
import type { LiveLogRecord } from "../logs/sse";
import { LiveLogController } from "../logs/controller";
import {
  createSameOriginLiveLogAccessProvider,
  type LiveLogAccessProvider,
} from "../logs/protocol";
import {
  applyLogRecord,
  isNearLogBottom,
  orderedLogGroups,
  projectVisibleLogGroups,
  replayLogRecords,
  toggleSet,
  type LogGroupView,
} from "../presenters/jobLogs";
import type { JobLogsViewState, LogConnectionState } from "../viewModels/jobLogs";

export function useJobLogs({
  access,
  initialRecords,
  model,
}: {
  readonly access?: LiveLogAccessProvider;
  readonly initialRecords: readonly LiveLogRecord[];
  readonly model: JobLogPageModel;
}): JobLogsViewState {
  const initialStateRef = useRef<ReturnType<typeof replayLogRecords> | null>(null);
  initialStateRef.current ??= replayLogRecords(initialRecords);
  const groupsRef = useRef(initialStateRef.current.groups);
  const [groups, setGroups] = useState<readonly LogGroupView[]>(initialStateRef.current.ordered);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(initialStateRef.current.expanded);
  const [query, setQuery] = useState("");
  const [connection, setConnection] = useState<LogConnectionState>("idle");
  const [following, setFollowing] = useState(true);
  const followingRef = useRef(true);
  const [streamError, setStreamError] = useState<string | null>(null);
  const viewerRef = useRef<HTMLDivElement>(null);
  const shouldScrollRef = useRef(false);

  useEffect(() => {
    if (model.live === null || model.logVisibility !== "full") return undefined;
    const controller = new LiveLogController({
      access:
        access ??
        createSameOriginLiveLogAccessProvider({ endpoint: model.live.ticketHref }),
      onRecord: (record) => {
        shouldScrollRef.current = followingRef.current && isNearLogBottom(viewerRef.current);
        applyLogRecord(groupsRef.current, record);
        setGroups(orderedLogGroups(groupsRef.current));
        if (record.type === "group_started") {
          setExpanded((current) => new Set(current).add(record.group.id));
        } else if (record.type === "group_finished") {
          setExpanded((current) => {
            const next = new Set(current);
            if (record.conclusion === "success") next.delete(record.groupId);
            else next.add(record.groupId);
            return next;
          });
        }
      },
      onStateChange: (state) => setConnection(state.kind),
      onFailure: () => setStreamError("The log stream could not be opened. Refresh the page to try again."),
    });
    const start = () => {
      void controller.start().catch(() => setStreamError("The log stream could not be opened."));
    };
    const visibilityChanged = () => {
      if (document.visibilityState === "visible") start();
      else controller.pause();
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    visibilityChanged();
    return () => {
      document.removeEventListener("visibilitychange", visibilityChanged);
      controller.dispose();
    };
  }, [access, model.live, model.logVisibility]);

  useLayoutEffect(() => {
    if (!shouldScrollRef.current) return;
    viewerRef.current?.scrollTo({ top: viewerRef.current.scrollHeight });
    shouldScrollRef.current = false;
  }, [groups]);

  const visibleGroups = useMemo(() => projectVisibleLogGroups(groups, query), [groups, query]);
  const canExpand = visibleGroups.length === 0 || visibleGroups.some((group) => !expanded.has(group.id));
  const running = model.job.status.tone === "queued" || model.job.status.tone === "running";
  const logToolsAvailable = model.live !== null || groups.length > 0 || running;

  const onToggleAll = useCallback(() => {
    setExpanded(canExpand ? new Set(visibleGroups.map((group) => group.id)) : new Set());
  }, [canExpand, visibleGroups]);
  const onToggleFollowing = useCallback(() => {
    followingRef.current = !followingRef.current;
    setFollowing(followingRef.current);
    if (followingRef.current) {
      viewerRef.current?.scrollTo({ top: viewerRef.current.scrollHeight });
    }
  }, []);
  const onToggleGroup = useCallback((id: string) => {
    setExpanded((current) => toggleSet(current, id));
  }, []);
  const onViewerScroll = useCallback(() => {
    if (!isNearLogBottom(viewerRef.current)) {
      followingRef.current = false;
      setFollowing(false);
    }
  }, []);

  return {
    canExpand,
    connection,
    expanded,
    following,
    logToolsAvailable,
    onQueryChange: setQuery,
    onToggleAll,
    onToggleFollowing,
    onToggleGroup,
    onViewerScroll,
    query,
    running,
    streamError,
    viewerRef,
    visibleGroups,
  };
}
