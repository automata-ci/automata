import {
  LiveLogProtocolError,
  LiveLogRequestError,
  liveLogTransportUrl,
  validateLiveLogAccess,
  validateLiveLogCheckpoint,
  type LiveLogAccess,
  type LiveLogAccessProvider,
  type LiveLogFetch,
  type LiveLogTransportCapability,
} from "./protocol";
import {
  LiveLogSseError,
  connectLiveLogSse,
  type LiveLogRecord,
} from "./sse";

const DEFAULT_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;
const DEFAULT_MAX_CONSECUTIVE_FAILURES = 5;

export interface LiveLogControllerOptions {
  readonly access: LiveLogAccessProvider;
  readonly onRecord: (
    record: LiveLogRecord,
    checkpoint: string,
  ) => void | Promise<void>;
  readonly onComplete?: (checkpoint: string | null) => void | Promise<void>;
  readonly onFailure?: (failure: LiveLogFailure) => void | Promise<void>;
  readonly onStateChange?: (state: LiveLogControllerState) => void;
  readonly initialCheckpoint?: string | null;
  readonly fetch?: LiveLogFetch;
  /** Number of failed connection attempts before delivery stops. */
  readonly maxConsecutiveFailures?: number;
}

export type LiveLogControllerState =
  | { readonly kind: "connecting"; readonly attempt: number }
  | { readonly kind: "open" }
  | {
      readonly kind: "reconnecting";
      readonly attempt: number;
      readonly delayMs: number;
    }
  | { readonly kind: "paused" }
  | { readonly kind: "complete" }
  | { readonly kind: "failed"; readonly failure: LiveLogFailure };

export interface LiveLogFailure {
  readonly code: "ticket" | "transport" | "protocol" | "network" | "client";
  readonly message: string;
}

interface RecordIdentity {
  readonly streamId: string;
  readonly sequence: string;
  readonly fragment: number | null;
}

interface LiveLogTransportDriver {
  readonly kind: string;
  readonly method: string;
  connect(options: LiveLogTransportConnection): Promise<LiveLogTransportResult>;
}

type LiveLogTransportResult =
  | { readonly kind: "complete"; readonly checkpoint: string }
  | { readonly kind: "reconnect" };

interface LiveLogTransportConnection {
  readonly access: LiveLogAccess;
  readonly capability: LiveLogTransportCapability;
  readonly checkpoint: string | null;
  readonly signal: AbortSignal;
  readonly fetch: LiveLogFetch;
  readonly onOpen: () => void;
  readonly onRetry: (milliseconds: number) => void;
  readonly onRecord: (
    record: LiveLogRecord,
    checkpoint: string,
  ) => void | Promise<void>;
}

const SSE_TRANSPORT: LiveLogTransportDriver = {
  kind: "sse",
  method: "POST",
  connect: (options) =>
    connectLiveLogSse({
      url: liveLogTransportUrl(options.access, options.capability),
      ticket: options.access.ticket,
      checkpoint: options.checkpoint,
      signal: options.signal,
      fetch: options.fetch,
      onOpen: options.onOpen,
      onRetry: options.onRetry,
      onRecord: options.onRecord,
    }),
};

/** Ordered by preference; future transports slot in without changing replay. */
const TRANSPORTS: readonly LiveLogTransportDriver[] = [SSE_TRANSPORT];

/**
 * Owns resumable live delivery while leaving identity/session policy to the
 * supplied ticket provider. Pausing retains only the non-secret checkpoint.
 */
export class LiveLogController {
  readonly #options: LiveLogControllerOptions;
  readonly #fetch: LiveLogFetch;
  readonly #maximumFailures: number;
  #checkpoint: string | null;
  #lastRecord: RecordIdentity | null = null;
  #abort: AbortController | null = null;
  #running: Promise<void> | null = null;
  #disposed = false;
  #terminal = false;
  #retryMs = DEFAULT_RETRY_MS;

  constructor(options: LiveLogControllerOptions) {
    this.#options = options;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#maximumFailures =
      options.maxConsecutiveFailures ?? DEFAULT_MAX_CONSECUTIVE_FAILURES;
    if (
      !Number.isInteger(this.#maximumFailures) ||
      this.#maximumFailures < 0 ||
      this.#maximumFailures > 100
    ) {
      throw new TypeError("maxConsecutiveFailures must be between 0 and 100");
    }
    this.#checkpoint =
      options.initialCheckpoint === undefined ||
      options.initialCheckpoint === null
        ? null
        : validateLiveLogCheckpoint(options.initialCheckpoint);
  }

  get checkpoint(): string | null {
    return this.#checkpoint;
  }

  get running(): boolean {
    return this.#running !== null;
  }

  /** Starts or resumes delivery. Concurrent starts share one run. */
  start(): Promise<void> {
    if (this.#disposed) {
      return Promise.reject(new Error("the live-log controller is disposed"));
    }
    if (this.#terminal) {
      return Promise.resolve();
    }
    if (this.#running !== null) {
      if (this.#abort?.signal.aborted === true) {
        return this.#running.then(() => this.start());
      }
      return this.#running;
    }
    const abort = new AbortController();
    this.#abort = abort;
    const run = this.#run(abort.signal);
    this.#running = run;
    void run.then(
      () => {
        if (this.#running === run) {
          this.#running = null;
          this.#abort = null;
        }
      },
      () => {
        if (this.#running === run) {
          this.#running = null;
          this.#abort = null;
        }
      },
    );
    return run;
  }

  /** Stops network work while preserving the checkpoint for a later start. */
  pause(): void {
    if (this.#terminal) {
      return;
    }
    this.#abort?.abort();
    if (!this.#disposed) {
      this.#emit({ kind: "paused" });
    }
  }

  dispose(): void {
    this.#disposed = true;
    this.#abort?.abort();
  }

  async #run(signal: AbortSignal): Promise<void> {
    let failures = 0;
    for (;;) {
      if (signal.aborted) {
        return;
      }
      this.#emit({ kind: "connecting", attempt: failures + 1 });
      try {
        const access = validateLiveLogAccess(await this.#options.access(signal));
        const selected = selectTransport(access);
        const result = await selected.driver.connect({
          access,
          capability: selected.capability,
          checkpoint: this.#checkpoint,
          signal,
          fetch: this.#fetch,
          onOpen: () => {
            this.#emit({ kind: "open" });
          },
          onRetry: (milliseconds) => {
            this.#retryMs = milliseconds;
          },
          onRecord: async (record, checkpoint) => {
            if (await this.#acceptRecord(record, checkpoint)) {
              failures = 0;
            }
          },
        });
        if (result.kind === "complete") {
          this.#checkpoint = validateLiveLogCheckpoint(result.checkpoint);
          this.#terminal = true;
          await this.#options.onComplete?.(this.#checkpoint);
          this.#emit({ kind: "complete" });
          return;
        }
        failures = 0;
        this.#emit({ kind: "reconnecting", attempt: 1, delayMs: 0 });
        continue;
      } catch (error) {
        if (signal.aborted || isAbortError(error)) {
          return;
        }
        failures += 1;
        const failure = safeFailure(error);
        if (
          failure.code === "protocol" ||
          failure.code === "client" ||
          failures > this.#maximumFailures
        ) {
          this.#terminal = true;
          this.#emit({ kind: "failed", failure });
          await this.#options.onFailure?.(failure);
          return;
        }
        const delayMs = Math.min(
          this.#retryMs * 2 ** Math.max(failures - 1, 0),
          MAX_RETRY_MS,
        );
        this.#emit({ kind: "reconnecting", attempt: failures + 1, delayMs });
        await abortableDelay(delayMs, signal);
      }
    }
  }

  async #acceptRecord(
    record: LiveLogRecord,
    checkpoint: string,
  ): Promise<boolean> {
    const nextCheckpoint = validateLiveLogCheckpoint(checkpoint);
    if (this.#lastRecord !== null) {
      if (record.streamId !== this.#lastRecord.streamId) {
        throw new LiveLogProtocolError("the live-log stream identity changed");
      }
      const order = compareRecord(record, this.#lastRecord);
      if (order < 0) {
        throw new LiveLogProtocolError("the live-log sequence moved backwards");
      }
      if (order === 0) {
        this.#checkpoint = nextCheckpoint;
        return false;
      }
    }
    await this.#options.onRecord(record, nextCheckpoint);
    this.#lastRecord = {
      streamId: record.streamId,
      sequence: record.sequence,
      fragment: record.fragment,
    };
    this.#checkpoint = nextCheckpoint;
    return true;
  }

  #emit(state: LiveLogControllerState): void {
    this.#options.onStateChange?.(state);
  }
}

function compareRecord(current: LiveLogRecord, previous: RecordIdentity): number {
  const sequence = compareDecimal(current.sequence, previous.sequence);
  if (sequence !== 0) {
    return sequence;
  }
  if (current.fragment === previous.fragment) {
    return 0;
  }
  if (current.fragment === null || previous.fragment === null) {
    return -1;
  }
  return current.fragment < previous.fragment ? -1 : 1;
}

function selectTransport(access: LiveLogAccess): {
  readonly driver: LiveLogTransportDriver;
  readonly capability: LiveLogTransportCapability;
} {
  for (const driver of TRANSPORTS) {
    const capability = access.transports.find(
      (candidate) =>
        candidate.kind === driver.kind && candidate.method === driver.method,
    );
    if (capability !== undefined) {
      return { driver, capability };
    }
  }
  throw new LiveLogProtocolError("Core did not advertise a supported transport");
}

function compareDecimal(left: string, right: string): number {
  if (left.length !== right.length) {
    return left.length < right.length ? -1 : 1;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}

function safeFailure(error: unknown): LiveLogFailure {
  if (error instanceof LiveLogProtocolError) {
    return { code: "protocol", message: error.message };
  }
  if (error instanceof LiveLogRequestError) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof LiveLogSseError) {
    return {
      code:
        error.code === "protocol"
          ? "protocol"
          : error.code === "network"
            ? "network"
            : "transport",
      message: error.message,
    };
  }
  return { code: "client", message: "the live-log client failed" };
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const timer = globalThis.setTimeout(finished, milliseconds);
    signal.addEventListener("abort", finished, { once: true });
    function finished() {
      globalThis.clearTimeout(timer);
      signal.removeEventListener("abort", finished);
      resolve();
    }
  });
}
