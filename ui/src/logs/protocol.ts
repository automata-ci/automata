export const LIVE_LOG_PROTOCOL_VERSION = 3 as const;

const TICKET = /^allt_v3_[A-Za-z0-9_-]{43}$/u;
const CHECKPOINT = /^[A-Za-z0-9_-]{1,512}$/u;
const TRANSPORT_KIND = /^[a-z][a-z0-9-]{0,31}$/u;
const MAX_TICKET_RESPONSE_BYTES = 32 * 1024;
const MAX_TRANSPORTS = 8;

export interface LiveLogTransportCapability {
  readonly kind: string;
  readonly method: string;
  readonly path: string;
}

/** Normalized result supplied by either Core or Automata Cloud. */
export interface LiveLogAccess {
  readonly protocolVersion: typeof LIVE_LOG_PROTOCOL_VERSION;
  readonly ticket: string;
  readonly expiresAtMs: number;
  /** Trusted origin on which the advertised transport paths are served. */
  readonly logsOrigin: string;
  readonly transports: readonly LiveLogTransportCapability[];
}

export type LiveLogAccessProvider = (
  signal: AbortSignal,
) => Promise<LiveLogAccess>;

export type LiveLogFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface SameOriginLiveLogAccessProviderOptions {
  /** Same-origin Core endpoint ending in `/live-ticket`. */
  readonly endpoint: string;
  /** Explicit document URL for non-browser consumers and tests. */
  readonly documentUrl?: string;
  readonly fetch?: LiveLogFetch;
}

interface CoreTicketResponse {
  readonly protocolVersion: typeof LIVE_LOG_PROTOCOL_VERSION;
  readonly ticket: string;
  readonly expiresAtMs: number;
  readonly transports: readonly LiveLogTransportCapability[];
}

/**
 * Builds the ticket adapter used by the embedded, self-hosted UI. Cloud uses
 * the same controller with an adapter for its own authenticated API response.
 */
export function createSameOriginLiveLogAccessProvider(
  options: SameOriginLiveLogAccessProviderOptions,
): LiveLogAccessProvider {
  return async (signal) => {
    const documentUrl =
      options.documentUrl ?? globalThis.location?.href;
    if (documentUrl === undefined) {
      throw new LiveLogProtocolError("a document URL is required");
    }
    const document = parseHttpUrl(documentUrl, "document URL");
    const endpoint = new URL(options.endpoint, document);
    if (
      endpoint.origin !== document.origin ||
      endpoint.username !== "" ||
      endpoint.password !== "" ||
      endpoint.search !== "" ||
      endpoint.hash !== ""
    ) {
      throw new LiveLogProtocolError("the ticket endpoint must be same-origin");
    }
    const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    const response = await fetcher(endpoint, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      method: "POST",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal,
    });
    if (!response.ok) {
      throw new LiveLogRequestError(
        "ticket",
        `the live-log ticket endpoint returned ${response.status}`,
        response.status >= 500 ||
          response.status === 408 ||
          response.status === 429,
      );
    }
    const length = response.headers.get("Content-Length");
    if (length !== null && Number(length) > MAX_TICKET_RESPONSE_BYTES) {
      throw new LiveLogProtocolError("the ticket response is too large");
    }
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > MAX_TICKET_RESPONSE_BYTES) {
      throw new LiveLogProtocolError("the ticket response is too large");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(body) as unknown;
    } catch {
      throw new LiveLogProtocolError("the ticket response is not valid JSON");
    }
    const ticket = parseCoreTicketResponse(decoded);
    return validateLiveLogAccess({
      ...ticket,
      logsOrigin: document.origin,
    });
  };
}

export function validateLiveLogAccess(value: LiveLogAccess): LiveLogAccess {
  const access = plainRecord(value, "live-log access");
  exactKeys(access, [
    "protocolVersion",
    "ticket",
    "expiresAtMs",
    "logsOrigin",
    "transports",
  ], "live-log access");
  if (access.protocolVersion !== LIVE_LOG_PROTOCOL_VERSION) {
    throw new LiveLogProtocolError("the live-log protocol version is unsupported");
  }
  const ticket = boundedString(access.ticket, 51, 51, "ticket");
  if (!TICKET.test(ticket)) {
    throw new LiveLogProtocolError("the live-log ticket is not canonical");
  }
  const expiresAtMs = safeInteger(access.expiresAtMs, 1, "ticket expiry");
  const logsOrigin = canonicalOrigin(access.logsOrigin);
  if (!Array.isArray(access.transports) || access.transports.length === 0) {
    throw new LiveLogProtocolError("at least one live-log transport is required");
  }
  if (access.transports.length > MAX_TRANSPORTS) {
    throw new LiveLogProtocolError("too many live-log transports were advertised");
  }
  const transports = access.transports.map((transport) =>
    validateTransport(transport),
  );
  return {
    protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
    ticket,
    expiresAtMs,
    logsOrigin,
    transports,
  };
}

export function validateLiveLogCheckpoint(value: string): string {
  if (!CHECKPOINT.test(value)) {
    throw new LiveLogProtocolError("the live-log checkpoint is not canonical");
  }
  return value;
}

export function liveLogTransportUrl(
  access: LiveLogAccess,
  transport: LiveLogTransportCapability,
): URL {
  const origin = canonicalOrigin(access.logsOrigin);
  if (!transport.path.startsWith("/") || transport.path.includes("\\")) {
    throw new LiveLogProtocolError("the live-log transport path is invalid");
  }
  const url = new URL(transport.path, `${origin}/`);
  if (
    url.origin !== origin ||
    url.pathname !== transport.path ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new LiveLogProtocolError("the live-log transport escaped its origin");
  }
  return url;
}

export class LiveLogProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LiveLogProtocolError";
  }
}

export class LiveLogRequestError extends Error {
  readonly code: "ticket" | "transport";
  readonly retryable: boolean;

  constructor(
    code: "ticket" | "transport",
    message: string,
    retryable = true,
  ) {
    super(message);
    this.name = "LiveLogRequestError";
    this.code = code;
    this.retryable = retryable;
  }
}

function parseCoreTicketResponse(value: unknown): CoreTicketResponse {
  const ticket = plainRecord(value, "ticket response");
  exactKeys(ticket, [
    "protocolVersion",
    "ticket",
    "expiresAtMs",
    "transports",
  ], "ticket response");
  return {
    protocolVersion: ticket.protocolVersion as typeof LIVE_LOG_PROTOCOL_VERSION,
    ticket: ticket.ticket as string,
    expiresAtMs: ticket.expiresAtMs as number,
    transports: ticket.transports as readonly LiveLogTransportCapability[],
  };
}

function validateTransport(value: unknown): LiveLogTransportCapability {
  const transport = plainRecord(value, "transport capability");
  exactKeys(transport, ["kind", "method", "path"], "transport capability");
  const kind = boundedString(transport.kind, 32, 1, "transport kind");
  if (!TRANSPORT_KIND.test(kind)) {
    throw new LiveLogProtocolError("the live-log transport kind is invalid");
  }
  const method = boundedString(transport.method, 16, 1, "transport method");
  if (!/^[A-Z]+$/u.test(method)) {
    throw new LiveLogProtocolError("the live-log transport method is invalid");
  }
  const path = boundedString(transport.path, 1_024, 1, "transport path");
  return { kind, method, path };
}

function canonicalOrigin(value: unknown): string {
  const origin = boundedString(value, 2_048, 1, "logs origin");
  const parsed = parseHttpUrl(origin, "logs origin");
  if (
    parsed.origin !== origin ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new LiveLogProtocolError("the logs origin is not canonical");
  }
  return origin;
}

function parseHttpUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new LiveLogProtocolError(`the ${label} is invalid`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new LiveLogProtocolError(`the ${label} must use HTTP`);
  }
  return parsed;
}

function plainRecord(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new LiveLogProtocolError(`the ${label} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => !expected.has(key))
  ) {
    throw new LiveLogProtocolError(`the ${label} has unexpected fields`);
  }
}

function boundedString(
  value: unknown,
  maximum: number,
  minimum: number,
  label: string,
): string {
  if (typeof value !== "string") {
    throw new LiveLogProtocolError(`the ${label} must be a string`);
  }
  const size = new TextEncoder().encode(value).byteLength;
  if (size < minimum || size > maximum) {
    throw new LiveLogProtocolError(`the ${label} has an invalid size`);
  }
  return value;
}

function safeInteger(value: unknown, minimum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new LiveLogProtocolError(`the ${label} must be a safe integer`);
  }
  return value as number;
}
