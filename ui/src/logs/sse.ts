import {
  LIVE_LOG_PROTOCOL_VERSION,
  LiveLogProtocolError,
  type LiveLogFetch,
} from "./protocol";

const MAX_SSE_CHUNK_BYTES = 1024 * 1024;
const MAX_SSE_BUFFER_CODE_UNITS = 1024 * 1024;
const MAX_SSE_EVENT_CODE_UNITS = 512 * 1024;
const MAX_LOG_OUTPUT_BYTES = 48 * 1024;
const MAX_LOG_OUTPUT_BASE64_BYTES = 64 * 1024;
const MAX_U64_DECIMAL = "18446744073709551615";
const MAX_U32 = 4_294_967_295;
const MIN_TIMESTAMP_MS = -62_167_219_200_000;
const MAX_TIMESTAMP_MS = 253_402_300_799_999;
const STREAM_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const GROUP_ID = /^[A-Za-z0-9:._/-]{1,256}$/u;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;
const BIDI_FORMATTING_CHARACTER =
  /[\u061c\u200e-\u200f\u202a-\u202e\u2066-\u2069]/u;

export type LiveLogChannel = "stdout" | "stderr" | "system";

interface LiveLogRecordBase {
  readonly streamId: string;
  /** Canonical decimal text keeps the Core u64 sequence lossless in JS. */
  readonly sequence: string;
  readonly emittedAtMs: number;
}

export type LiveLogGroupKind =
  | "setup"
  | "step"
  | "action_pre"
  | "action_post"
  | "cleanup";

export interface LiveLogGroup {
  readonly id: string;
  readonly parentId: string | null;
  readonly name: string;
  readonly kind: LiveLogGroupKind;
  readonly ordinal: number;
}

export interface LiveLogGroupStartedRecord extends LiveLogRecordBase {
  readonly type: "group_started";
  readonly group: LiveLogGroup;
}

export interface LiveLogOutputRecord extends LiveLogRecordBase {
  readonly type: "output";
  readonly groupId: string;
  readonly channel: LiveLogChannel;
  readonly part: number;
  readonly data: Uint8Array;
}

export interface LiveLogGroupFinishedRecord extends LiveLogRecordBase {
  readonly type: "group_finished";
  readonly groupId: string;
  readonly conclusion: "success" | "failure" | "cancelled" | "timed_out" | "skipped";
}

export type LiveLogRecord =
  | LiveLogGroupStartedRecord
  | LiveLogOutputRecord
  | LiveLogGroupFinishedRecord;

export interface SseConnectionOptions {
  readonly url: URL;
  readonly ticket: string;
  readonly checkpoint: string | null;
  readonly signal: AbortSignal;
  readonly fetch: LiveLogFetch;
  readonly onRecord: (
    record: LiveLogRecord,
    checkpoint: string,
  ) => void | Promise<void>;
  readonly onOpen?: () => void;
  readonly onRetry?: (milliseconds: number) => void;
}

export type SseConnectionResult =
  | { readonly kind: "complete"; readonly checkpoint: string }
  | { readonly kind: "reconnect" };

interface DecodedSseEvent {
  readonly event: string | null;
  readonly data: string | null;
  readonly id: string | null;
  readonly retry: number | null;
}

interface ProtocolEnvelope {
  readonly protocolVersion: typeof LIVE_LOG_PROTOCOL_VERSION;
}

interface ErrorEnvelope extends ProtocolEnvelope {
  readonly error: string;
}

export async function connectLiveLogSse(
  options: SseConnectionOptions,
): Promise<SseConnectionResult> {
  const headers = new Headers({
    Accept: "text/event-stream",
    Authorization: `AutomataLogTicket ${options.ticket}`,
  });
  if (options.checkpoint !== null) {
    headers.set("Last-Event-ID", options.checkpoint);
  }
  const response = await options.fetch(options.url, {
    credentials: "omit",
    headers,
    method: "POST",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal: options.signal,
  });
  if (!response.ok) {
    throw new LiveLogSseError(
      "http",
      `the live-log transport returned ${response.status}`,
    );
  }
  const contentType = response.headers.get("Content-Type")?.toLowerCase();
  if (contentType?.startsWith("text/event-stream") !== true) {
    throw new LiveLogSseError(
      "protocol",
      "the live-log transport did not return an event stream",
    );
  }
  if (response.body === null) {
    throw new LiveLogSseError(
      "protocol",
      "the live-log transport returned no body",
    );
  }
  options.onOpen?.();

  const reader = response.body.getReader();
  const text = new TextDecoder("utf-8", { fatal: true });
  const decoder = new SseDecoder();
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        try {
          text.decode();
        } catch {
          throw new LiveLogSseError(
            "protocol",
            "the live-log stream ended within a UTF-8 character",
          );
        }
        throw new LiveLogSseError(
          "network",
          "the live-log stream ended before completion",
        );
      }
      if (chunk.value.byteLength > MAX_SSE_CHUNK_BYTES) {
        throw new LiveLogSseError("protocol", "a live-log chunk is too large");
      }
      let decoded: string;
      try {
        decoded = text.decode(chunk.value, { stream: true });
      } catch {
        throw new LiveLogSseError(
          "protocol",
          "the live-log stream is not valid UTF-8",
        );
      }
      const events = decoder.push(decoded);
      for (const event of events) {
        if (event.retry !== null) {
          options.onRetry?.(event.retry);
        }
        if (event.data === null) {
          continue;
        }
        switch (event.event ?? "message") {
          case "log": {
            if (event.id === null) {
              throw new LiveLogSseError(
                "protocol",
                "a live-log record has no checkpoint",
              );
            }
            await options.onRecord(parseLogRecord(event.data), event.id);
            break;
          }
          case "complete":
            if (event.id === null) {
              throw new LiveLogSseError(
                "protocol",
                "the live-log completion has no checkpoint",
              );
            }
            parseProtocolEnvelope(event.data, "completion");
            return { kind: "complete", checkpoint: event.id };
          case "reconnect":
            parseProtocolEnvelope(event.data, "reconnect");
            return { kind: "reconnect" };
          case "error": {
            const error = parseErrorEnvelope(event.data);
            throw new LiveLogSseError(
              "server",
              `Core ended the live-log stream: ${error.error}`,
            );
          }
          default:
            throw new LiveLogSseError(
              "protocol",
              "the live-log stream contains an unsupported event",
            );
        }
      }
    }
  } catch (error) {
    if (error instanceof LiveLogProtocolError) {
      throw new LiveLogSseError("protocol", error.message);
    }
    throw error;
  } finally {
    try {
      await reader.cancel();
    } catch {
      // The connection may already have failed or been aborted.
    }
    reader.releaseLock();
  }
}

export class LiveLogSseError extends Error {
  readonly code: "http" | "network" | "protocol" | "server";

  constructor(
    code: "http" | "network" | "protocol" | "server",
    message: string,
  ) {
    super(message);
    this.name = "LiveLogSseError";
    this.code = code;
  }
}

class SseDecoder {
  #buffer = "";
  #eventName: string | null = null;
  #data: string[] = [];
  #id: string | null = null;
  #retry: number | null = null;
  #eventSize = 0;

  push(chunk: string): readonly DecodedSseEvent[] {
    this.#buffer += chunk;
    if (this.#buffer.length > MAX_SSE_BUFFER_CODE_UNITS) {
      throw new LiveLogSseError("protocol", "the live-log buffer is too large");
    }
    const events: DecodedSseEvent[] = [];
    for (;;) {
      const boundary = lineBoundary(this.#buffer);
      if (boundary === null) {
        break;
      }
      const line = this.#buffer.slice(0, boundary.index);
      this.#buffer = this.#buffer.slice(boundary.index + boundary.length);
      const event = this.#acceptLine(line);
      if (event !== null) {
        events.push(event);
      }
    }
    return events;
  }

  #acceptLine(line: string): DecodedSseEvent | null {
    this.#eventSize += line.length + 1;
    if (this.#eventSize > MAX_SSE_EVENT_CODE_UNITS) {
      throw new LiveLogSseError("protocol", "a live-log event is too large");
    }
    if (line === "") {
      const event =
        this.#data.length > 0 || this.#retry !== null
          ? {
              event: this.#eventName,
              data: this.#data.length > 0 ? this.#data.join("\n") : null,
              id: this.#id,
              retry: this.#retry,
            }
          : null;
      this.#eventName = null;
      this.#data = [];
      this.#id = null;
      this.#retry = null;
      this.#eventSize = 0;
      return event;
    }
    if (line.startsWith(":")) {
      return null;
    }
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    switch (field) {
      case "event":
        if (this.#eventName !== null) {
          throw new LiveLogSseError("protocol", "a live-log event repeats its type");
        }
        this.#eventName = value;
        break;
      case "data":
        this.#data.push(value);
        break;
      case "id":
        if (this.#id !== null || value.includes("\0")) {
          throw new LiveLogSseError("protocol", "a live-log event has an invalid ID");
        }
        this.#id = value;
        break;
      case "retry":
        if (this.#retry !== null) {
          throw new LiveLogSseError(
            "protocol",
            "a live-log event repeats its retry delay",
          );
        }
        if (/^[0-9]+$/u.test(value)) {
          const parsed = Number(value);
          if (Number.isSafeInteger(parsed)) {
            this.#retry = Math.min(Math.max(parsed, 250), 30_000);
          }
        }
        break;
      default:
        // Unknown SSE fields are explicitly ignored by the event-stream format.
        break;
    }
    return null;
  }
}

function parseLogRecord(data: string): LiveLogRecord {
  const record = parseJsonRecord(data, "log record");
  const commonKeys = [
    "protocolVersion",
    "streamId",
    "sequence",
    "emittedAtMs",
    "type",
  ];
  if (record.protocolVersion !== LIVE_LOG_PROTOCOL_VERSION) {
    throw new LiveLogProtocolError("the log record protocol version is unsupported");
  }
  if (typeof record.streamId !== "string" || !STREAM_ID.test(record.streamId)) {
    throw new LiveLogProtocolError("the log record stream ID is invalid");
  }
  if (
    typeof record.sequence !== "string" ||
    !DECIMAL.test(record.sequence) ||
    compareDecimal(record.sequence, MAX_U64_DECIMAL) > 0
  ) {
    throw new LiveLogProtocolError("the log record sequence is invalid");
  }
  if (
    !Number.isSafeInteger(record.emittedAtMs) ||
    (record.emittedAtMs as number) < MIN_TIMESTAMP_MS ||
    (record.emittedAtMs as number) > MAX_TIMESTAMP_MS
  ) {
    throw new LiveLogProtocolError("the log record timestamp is invalid");
  }
  const base = {
    streamId: record.streamId,
    sequence: record.sequence,
    emittedAtMs: record.emittedAtMs as number,
  };
  switch (record.type) {
    case "group_started":
      exactKeys(record, [...commonKeys, "group"], "group-started log record");
      return { ...base, type: "group_started", group: parseLogGroup(record.group) };
    case "output": {
      exactKeys(record, [...commonKeys, "groupId", "channel", "part", "dataBase64"], "output log record");
      const groupId = logGroupId(record.groupId, "output group ID");
      if (
        record.channel !== "stdout" &&
        record.channel !== "stderr" &&
        record.channel !== "system"
      ) {
        throw new LiveLogProtocolError("the log record channel is invalid");
      }
      if (!Number.isInteger(record.part) || (record.part as number) < 0 || (record.part as number) > MAX_U32) {
        throw new LiveLogProtocolError("the log output part is invalid");
      }
      return {
        ...base,
        type: "output",
        groupId,
        channel: record.channel,
        part: record.part as number,
        data: decodeCanonicalBase64Url(record.dataBase64),
      };
    }
    case "group_finished":
      exactKeys(record, [...commonKeys, "groupId", "conclusion"], "group-finished log record");
      if (
        record.conclusion !== "success" &&
        record.conclusion !== "failure" &&
        record.conclusion !== "cancelled" &&
        record.conclusion !== "timed_out" &&
        record.conclusion !== "skipped"
      ) {
        throw new LiveLogProtocolError("the group conclusion is invalid");
      }
      return {
        ...base,
        type: "group_finished",
        groupId: logGroupId(record.groupId, "finished group ID"),
        conclusion: record.conclusion,
      };
    default:
      throw new LiveLogProtocolError("the log record type is unsupported");
  }
}

function parseLogGroup(value: unknown): LiveLogGroup {
  const group = parseJsonValueRecord(value, "log group");
  exactKeys(group, ["id", "parentId", "name", "kind", "ordinal"], "log group");
  const id = logGroupId(group.id, "group ID");
  const parentId = group.parentId === null ? null : logGroupId(group.parentId, "parent group ID");
  if (parentId === id) {
    throw new LiveLogProtocolError("a log group cannot contain itself");
  }
  if (
    typeof group.name !== "string" ||
    group.name.trim().length === 0 ||
    new TextEncoder().encode(group.name).byteLength > 512 ||
    CONTROL_CHARACTER.test(group.name) ||
    BIDI_FORMATTING_CHARACTER.test(group.name)
  ) {
    throw new LiveLogProtocolError("the log group name is invalid");
  }
  if (
    group.kind !== "setup" &&
    group.kind !== "step" &&
    group.kind !== "action_pre" &&
    group.kind !== "action_post" &&
    group.kind !== "cleanup"
  ) {
    throw new LiveLogProtocolError("the log group kind is invalid");
  }
  if (!Number.isInteger(group.ordinal) || (group.ordinal as number) < 0 || (group.ordinal as number) > MAX_U32) {
    throw new LiveLogProtocolError("the log group ordinal is invalid");
  }
  return { id, parentId, name: group.name, kind: group.kind, ordinal: group.ordinal as number };
}

function logGroupId(value: unknown, label: string): string {
  if (typeof value !== "string" || !GROUP_ID.test(value)) {
    throw new LiveLogProtocolError(`the ${label} is invalid`);
  }
  return value;
}

function decodeCanonicalBase64Url(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_LOG_OUTPUT_BASE64_BYTES ||
    value.length % 4 === 1
  ) {
    throw new LiveLogProtocolError("the log output data is invalid");
  }
  const outputLength = Math.floor(value.length * 6 / 8);
  if (outputLength === 0 || outputLength > MAX_LOG_OUTPUT_BYTES) {
    throw new LiveLogProtocolError("the log output data is invalid");
  }
  const output = new Uint8Array(outputLength);
  let input = 0;
  let written = 0;
  while (input + 4 <= value.length) {
    const first = base64UrlValue(value.charCodeAt(input));
    const second = base64UrlValue(value.charCodeAt(input + 1));
    const third = base64UrlValue(value.charCodeAt(input + 2));
    const fourth = base64UrlValue(value.charCodeAt(input + 3));
    if (first < 0 || second < 0 || third < 0 || fourth < 0) {
      throw new LiveLogProtocolError("the log output data is invalid");
    }
    output[written] = (first << 2) | (second >> 4);
    output[written + 1] = (second << 4) | (third >> 2);
    output[written + 2] = (third << 6) | fourth;
    input += 4;
    written += 3;
  }
  const remaining = value.length - input;
  if (remaining === 2) {
    const first = base64UrlValue(value.charCodeAt(input));
    const second = base64UrlValue(value.charCodeAt(input + 1));
    if (first < 0 || second < 0 || (second & 0x0f) !== 0) {
      throw new LiveLogProtocolError("the log output data is invalid");
    }
    output[written] = (first << 2) | (second >> 4);
  } else if (remaining === 3) {
    const first = base64UrlValue(value.charCodeAt(input));
    const second = base64UrlValue(value.charCodeAt(input + 1));
    const third = base64UrlValue(value.charCodeAt(input + 2));
    if (first < 0 || second < 0 || third < 0 || (third & 0x03) !== 0) {
      throw new LiveLogProtocolError("the log output data is invalid");
    }
    output[written] = (first << 2) | (second >> 4);
    output[written + 1] = (second << 4) | (third >> 2);
  } else if (remaining !== 0) {
    throw new LiveLogProtocolError("the log output data is invalid");
  }
  return output;
}

function base64UrlValue(code: number): number {
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 71;
  if (code >= 48 && code <= 57) return code + 4;
  if (code === 45) return 62;
  if (code === 95) return 63;
  return -1;
}

function parseProtocolEnvelope(data: string, label: string): ProtocolEnvelope {
  const envelope = parseJsonRecord(data, label);
  exactKeys(envelope, ["protocolVersion"], label);
  if (envelope.protocolVersion !== LIVE_LOG_PROTOCOL_VERSION) {
    throw new LiveLogProtocolError(`the ${label} protocol version is unsupported`);
  }
  return { protocolVersion: LIVE_LOG_PROTOCOL_VERSION };
}

function parseErrorEnvelope(data: string): ErrorEnvelope {
  const envelope = parseJsonRecord(data, "error event");
  exactKeys(envelope, ["protocolVersion", "error"], "error event");
  if (envelope.protocolVersion !== LIVE_LOG_PROTOCOL_VERSION) {
    throw new LiveLogProtocolError("the error protocol version is unsupported");
  }
  if (
    typeof envelope.error !== "string" ||
    !/^[a-z][a-z0-9_]{0,63}$/u.test(envelope.error)
  ) {
    throw new LiveLogProtocolError("the live-log error code is invalid");
  }
  return {
    protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
    error: envelope.error,
  };
}

function parseJsonRecord(data: string, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(data) as unknown;
  } catch {
    throw new LiveLogProtocolError(`the ${label} is not valid JSON`);
  }
  return parseJsonValueRecord(value, label);
}

function parseJsonValueRecord(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new LiveLogProtocolError(`the ${label} is not an object`);
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

function compareDecimal(left: string, right: string): number {
  if (left.length !== right.length) {
    return left.length < right.length ? -1 : 1;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}

function lineBoundary(
  value: string,
): { readonly index: number; readonly length: number } | null {
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\n") {
      return { index, length: 1 };
    }
    if (character === "\r") {
      if (index + 1 === value.length) {
        return null;
      }
      return {
        index,
        length: value[index + 1] === "\n" ? 2 : 1,
      };
    }
  }
  return null;
}
