import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client.js";

export type ResourceState<T> =
  | { status: "loading" }
  | { status: "ready"; data: T; refreshing: boolean }
  | { status: "error"; error: ApiError; previous: T | null };

export interface ResourceOptions {
  /** Poll interval while the tab is visible and while hidden (P04-D8). */
  poll?: { visibleMs: number; hiddenMs: number };
  enabled?: boolean;
}

/**
 * Stop polling after the tab has been hidden this long. Background polling
 * touches the session, so without a limit an idle, forgotten tab would never
 * reach the controller's 12-hour idle timeout.
 */
export const HIDDEN_POLL_LIMIT_MS = 15 * 60_000;

function asApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError(0, "network", error instanceof Error ? error.message : "Request failed");
}

/**
 * Load one controller resource. A failed read is an error state and never a
 * zero or an empty list; a failed refresh keeps the last good data visible
 * but reports the error alongside it.
 */
export function useResource<T>(key: string | null, loader: (signal: AbortSignal) => Promise<T>, options: ResourceOptions = {}) {
  const [state, setState] = useState<ResourceState<T>>({ status: "loading" });
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const dataRef = useRef<T | null>(null);
  const generation = useRef(0);
  const enabled = options.enabled !== false && key !== null;

  const run = useCallback(
    async (mode: "initial" | "refresh") => {
      const current = ++generation.current;
      const controller = new AbortController();
      if (mode === "initial") setState({ status: "loading" });
      else if (dataRef.current !== null) setState({ status: "ready", data: dataRef.current, refreshing: true });
      try {
        const data = await loaderRef.current(controller.signal);
        if (current !== generation.current) return;
        dataRef.current = data;
        setState({ status: "ready", data, refreshing: false });
      } catch (error) {
        if (current !== generation.current || controller.signal.aborted) return;
        setState({ status: "error", error: asApiError(error), previous: dataRef.current });
      }
    },
    []
  );

  useEffect(() => {
    dataRef.current = null;
    if (!enabled) return;
    void run("initial");
    return () => {
      generation.current += 1;
    };
  }, [key, enabled, run]);

  const pollVisible = options.poll?.visibleMs;
  const pollHidden = options.poll?.hiddenMs;
  useEffect(() => {
    if (!enabled || !pollVisible || !pollHidden) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let hiddenSince: number | null = document.visibilityState === "hidden" ? Date.now() : null;

    const schedule = () => {
      clearTimeout(timer);
      const hidden = document.visibilityState === "hidden";
      if (hidden && hiddenSince !== null && Date.now() - hiddenSince > HIDDEN_POLL_LIMIT_MS) return;
      timer = setTimeout(async () => {
        await run("refresh");
        schedule();
      }, hidden ? pollHidden : pollVisible);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        hiddenSince = Date.now();
        schedule();
      } else {
        const wasStopped = hiddenSince !== null && Date.now() - hiddenSince > HIDDEN_POLL_LIMIT_MS;
        hiddenSince = null;
        if (wasStopped) void run("refresh");
        schedule();
      }
    };
    schedule();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled, pollVisible, pollHidden, run, key]);

  const reload = useCallback(() => run(dataRef.current === null ? "initial" : "refresh"), [run]);
  const replace = useCallback((data: T) => {
    dataRef.current = data;
    setState({ status: "ready", data, refreshing: false });
  }, []);

  return { state, reload, replace };
}

export function resourceData<T>(state: ResourceState<T>): T | null {
  if (state.status === "ready") return state.data;
  if (state.status === "error") return state.previous;
  return null;
}

/** Fetch every page of a cursor list (used only where a full total is shown). */
export async function collectAll<T>(
  fetchPage: (cursor: string | null) => Promise<{ items: T[]; next_cursor: string | null }>,
  maxPages = 50
): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < maxPages; page += 1) {
    const result = await fetchPage(cursor);
    items.push(...result.items);
    if (!result.next_cursor) return items;
    cursor = result.next_cursor;
  }
  throw new ApiError(0, "too_many_pages", "The list is longer than the console will total.");
}
