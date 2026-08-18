import { describe, expect, it, vi } from "vitest";
import {
  LIVE_LOG_PROTOCOL_VERSION,
  LiveLogController,
  createSameOriginLiveLogAccessProvider,
  validateLiveLogAccess,
  type LiveLogAccess,
  type LiveLogFetch,
  type LiveLogFailure,
  type LiveLogRecord,
} from "../../src/logs";

const STREAM_ID = "00000000-0000-4000-8000-000000000005";
const TICKET_ONE = `allt_v3_${"A".repeat(43)}`;
const TICKET_TWO = `allt_v3_${"B".repeat(43)}`;

describe("same-origin live-log ticket acquisition", () => {
  it("keeps the credential in a validated response and derives Core's origin", async () => {
    const fetchMock = vi.fn<LiveLogFetch>(async () =>
      Response.json({
        protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
        ticket: TICKET_ONE,
        expiresAtMs: Date.now() + 60_000,
        transports: [{ kind: "sse", method: "POST", path: "/live/v3/logs" }],
      }),
    );
    const acquire = createSameOriginLiveLogAccessProvider({
      endpoint: "/octo/repo/actions/runs/run/jobs/job/live-ticket",
      documentUrl: "https://ci.example/octo/repo/actions/runs/run/jobs/job",
      fetch: fetchMock,
    });

    const access = await acquire(new AbortController().signal);

    expect(access).toEqual({
      protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
      ticket: TICKET_ONE,
      expiresAtMs: expect.any(Number),
      logsOrigin: "https://ci.example",
      transports: [{ kind: "sse", method: "POST", path: "/live/v3/logs" }],
    });
    const [input, init] = fetchMock.mock.calls[0] ?? [];
    expect((input as URL).href).toBe(
      "https://ci.example/octo/repo/actions/runs/run/jobs/job/live-ticket",
    );
    expect(init).toMatchObject({
      cache: "no-store",
      credentials: "same-origin",
      method: "POST",
      redirect: "error",
    });
    expect((input as URL).href).not.toContain(TICKET_ONE);
  });

  it("rejects a ticket endpoint outside the document origin", async () => {
    const fetchMock = vi.fn<LiveLogFetch>();
    const acquire = createSameOriginLiveLogAccessProvider({
      endpoint: "https://evil.invalid/live-ticket",
      documentUrl: "https://ci.example/jobs/1",
      fetch: fetchMock,
    });

    await expect(acquire(new AbortController().signal)).rejects.toThrow(
      "same-origin",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["HTTP failure", new Response(null, { status: 503 }), "returned 503"],
    [
      "declared oversized response",
      new Response("{}", { headers: { "Content-Length": "32769" } }),
      "too large",
    ],
    [
      "actual oversized response",
      new Response("x".repeat(32 * 1024 + 1)),
      "too large",
    ],
    ["malformed JSON", new Response("{"), "not valid JSON"],
  ])("rejects a %s", async (_name, response, message) => {
    const acquire = createSameOriginLiveLogAccessProvider({
      endpoint: "/jobs/1/live-ticket",
      documentUrl: "https://ci.example/jobs/1",
      fetch: async () => response,
    });

    await expect(acquire(new AbortController().signal)).rejects.toThrow(message);
  });
});

describe("live-log capability validation", () => {
  it.each([
    [null, "plain object"],
    [{ ...access(TICKET_ONE), extra: true }, "unexpected fields"],
    [{ ...access(TICKET_ONE), protocolVersion: 1 }, "version"],
    [{ ...access(TICKET_ONE), ticket: "not-a-ticket" }, "ticket"],
    [{ ...access(TICKET_ONE), expiresAtMs: 0 }, "safe integer"],
    [{ ...access(TICKET_ONE), logsOrigin: "not a URL" }, "invalid"],
    [{ ...access(TICKET_ONE), logsOrigin: "ftp://logs.example" }, "use HTTP"],
    [{ ...access(TICKET_ONE), logsOrigin: "https://logs.example/path" }, "canonical"],
    [{ ...access(TICKET_ONE), transports: [] }, "at least one"],
    [
      {
        ...access(TICKET_ONE),
        transports: Array.from({ length: 9 }, () => ({
          kind: "sse",
          method: "POST",
          path: "/live/v3/logs",
        })),
      },
      "too many",
    ],
    [{ ...access(TICKET_ONE), transports: [null] }, "plain object"],
    [
      {
        ...access(TICKET_ONE),
        transports: [{ kind: "SSE", method: "POST", path: "/live/v3/logs" }],
      },
      "kind",
    ],
    [
      {
        ...access(TICKET_ONE),
        transports: [{ kind: "sse", method: "post", path: "/live/v3/logs" }],
      },
      "method",
    ],
    [
      {
        ...access(TICKET_ONE),
        transports: [{ kind: "sse", method: "POST", path: 42 }],
      },
      "must be a string",
    ],
  ])("rejects invalid normalized access %#", (value, message) => {
    expect(() => validateLiveLogAccess(value as LiveLogAccess)).toThrow(message);
  });
});

describe("live-log ticket rejection", () => {
  it.each([401, 403, 404])(
    "fails immediately when the ticket endpoint returns %i",
    async (status) => {
      const ticketFetch = vi.fn<LiveLogFetch>(async () =>
        new Response(null, { status }),
      );
      const failure = vi.fn();
      const controller = new LiveLogController({
        access: createSameOriginLiveLogAccessProvider({
          endpoint: "/octo/repo/actions/runs/run/jobs/job/live-ticket",
          documentUrl: "https://ci.example/octo/repo/actions/runs/run/jobs/job",
          fetch: ticketFetch,
        }),
        onFailure: failure,
        onRecord: vi.fn(),
      });

      await controller.start();

      expect(ticketFetch).toHaveBeenCalledOnce();
      expect(failure).toHaveBeenCalledWith({
        code: "ticket",
        message: `the live-log ticket endpoint returned ${status}`,
      });
    },
  );
});

describe("live-log transport controller", () => {
  it("delivers group lifecycle records and scoped output in order", async () => {
    const records: LiveLogRecord[] = [];
    const payload = [
      recordEvent("checkpoint_1", {
        protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
        streamId: STREAM_ID,
        sequence: "1",
        emittedAtMs: 1_777_890_010_000,
        type: "group_started",
        group: {
          id: "phase/1",
          parentId: null,
          name: "Build",
          kind: "step",
          ordinal: 1,
        },
      }),
      logEvent("checkpoint_2", { sequence: "2", text: "building" }),
      recordEvent("checkpoint_3", {
        protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
        streamId: STREAM_ID,
        sequence: "3",
        emittedAtMs: 1_777_890_012_000,
        type: "group_finished",
        groupId: "phase/1",
        conclusion: "success",
      }),
      completeEvent("checkpoint_4"),
    ].join("");
    const controller = new LiveLogController({
      access: async () => access(TICKET_ONE),
      fetch: async () => eventStreamResponse(payload),
      onRecord: (record) => {
        records.push(record);
      },
    });

    await controller.start();

    expect(records.map((record) => record.type)).toEqual([
      "group_started",
      "output",
      "group_finished",
    ]);
    expect(records[0]).toMatchObject({
      group: { id: "phase/1", name: "Build", kind: "step", ordinal: 1 },
    });
    expect(records[1]).toMatchObject({ groupId: "phase/1", part: 0 });
    expect(records[1]?.type === "output" ? decodeText(records[1].data) : null).toBe("building");
    expect(records[2]).toMatchObject({
      groupId: "phase/1",
      conclusion: "success",
    });
  });

  it("decodes arbitrarily chunked UTF-8 records and advances after application", async () => {
    const applied: Array<{ record: LiveLogRecord; checkpoint: string }> = [];
    const states: string[] = [];
    const payload = [
      ": connected\r\nretry: 1250\r\n\r\n",
      logEvent("checkpoint_1", {
        sequence: "18446744073709551615",
        text: "compile café 🚀",
      }),
      completeEvent("checkpoint_2"),
    ].join("");
    const fetchMock = vi.fn<LiveLogFetch>(async () =>
      eventStreamResponse(payload, [1, 5, 37, 43]),
    );
    const controller = new LiveLogController({
      access: async () => access(TICKET_ONE),
      fetch: fetchMock,
      onRecord: (record, checkpoint) => {
        applied.push({ record, checkpoint });
      },
      onStateChange: (state) => states.push(state.kind),
    });

    await controller.start();

    expect(applied).toHaveLength(1);
    expect(applied[0]?.checkpoint).toBe("checkpoint_1");
    expect(applied[0]?.record).toMatchObject({
      streamId: STREAM_ID,
      sequence: "18446744073709551615",
      emittedAtMs: 1_777_890_010_000,
      type: "output",
      groupId: "phase/1",
      channel: "stdout",
      part: 0,
    });
    expect(applied[0]?.record.type === "output" ? decodeText(applied[0].record.data) : null).toBe("compile café 🚀");
    expect(controller.checkpoint).toBe("checkpoint_2");
    expect(states).toEqual(["connecting", "open", "complete"]);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect((url as URL).href).toBe("https://logs.example/live/v3/logs");
    expect((url as URL).href).not.toContain(TICKET_ONE);
    expect(init).toMatchObject({
      credentials: "omit",
      method: "POST",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    const headers = init?.headers;
    expect(headers).toBeInstanceOf(Headers);
    expect((headers as Headers).get("Authorization")).toBe(
      `AutomataLogTicket ${TICKET_ONE}`,
    );
    expect((headers as Headers).get("Last-Event-ID")).toBeNull();
  });

  it("gets a fresh ticket, resumes its checkpoint, and drops a replayed record", async () => {
    const records: LiveLogRecord[] = [];
    const tickets = [TICKET_ONE, TICKET_TWO];
    const acquire = vi.fn(async () => access(tickets.shift() ?? TICKET_TWO));
    const responses = [
      eventStreamResponse(
        `${logEvent("checkpoint_1", { sequence: "7", text: "first" })}` +
          "event: reconnect\ndata: {\"protocolVersion\":3}\n\n",
      ),
      eventStreamResponse(
        `${logEvent("checkpoint_1", { sequence: "7", text: "first" })}` +
          `${logEvent("checkpoint_2", { sequence: "8", text: "second" })}` +
          completeEvent("checkpoint_3"),
      ),
    ];
    const fetchMock = vi.fn<LiveLogFetch>(async () => {
      const response = responses.shift();
      if (response === undefined) {
        throw new Error("unexpected live-log request");
      }
      return response;
    });
    const controller = new LiveLogController({
      access: acquire,
      fetch: fetchMock,
      onRecord: (record) => {
        records.push(record);
      },
    });

    await controller.start();

    expect(acquire).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(records.filter((record) => record.type === "output").map((record) => decodeText(record.data))).toEqual(["first", "second"]);
    expect(controller.checkpoint).toBe("checkpoint_3");
    const firstHeaders = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    const secondHeaders = fetchMock.mock.calls[1]?.[1]?.headers as Headers;
    expect(firstHeaders.get("Authorization")).toContain(TICKET_ONE);
    expect(secondHeaders.get("Authorization")).toContain(TICKET_TWO);
    expect(secondHeaders.get("Last-Event-ID")).toBe("checkpoint_1");
  });

  it("does not advance a checkpoint when malformed data fails delivery", async () => {
    const failure = vi.fn();
    const malformed = logEvent("checkpoint_bad", {
      sequence: 9,
      text: "sequence must be lossless decimal text",
    });
    const acquire = vi.fn(async () => access(TICKET_ONE));
    const fetchMock = vi.fn<LiveLogFetch>(async () =>
      eventStreamResponse(malformed),
    );
    const controller = new LiveLogController({
      access: acquire,
      fetch: fetchMock,
      onRecord: vi.fn(),
      onFailure: failure,
    });

    await controller.start();

    expect(controller.checkpoint).toBeNull();
    expect(failure).toHaveBeenCalledWith({
      code: "protocol",
      message: "the log record sequence is invalid",
    });
    expect(acquire).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not restart after the stream reaches its terminal checkpoint", async () => {
    const acquire = vi.fn(async () => access(TICKET_ONE));
    const fetchMock = vi.fn<LiveLogFetch>(async () =>
      eventStreamResponse(completeEvent("checkpoint_terminal")),
    );
    const states: string[] = [];
    const controller = new LiveLogController({
      access: acquire,
      fetch: fetchMock,
      onRecord: vi.fn(),
      onStateChange: (state) => states.push(state.kind),
    });

    await controller.start();
    controller.pause();
    await controller.start();

    expect(controller.checkpoint).toBe("checkpoint_terminal");
    expect(acquire).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(states).toEqual(["connecting", "open", "complete"]);
  });

  it("replays a record when the UI has not successfully applied it", async () => {
    const failure = vi.fn();
    const controller = new LiveLogController({
      access: async () => access(TICKET_ONE),
      fetch: async () =>
        eventStreamResponse(
          logEvent("checkpoint_unapplied", { sequence: "12", text: "retry me" }),
        ),
      maxConsecutiveFailures: 0,
      onRecord: () => {
        throw new Error("render target unavailable");
      },
      onFailure: failure,
    });

    await controller.start();

    expect(controller.checkpoint).toBeNull();
    expect(failure).toHaveBeenCalledWith({
      code: "client",
      message: "the live-log client failed",
    });
  });

  it("rejects advertised transport paths that escape the trusted logs origin", async () => {
    const failure = vi.fn();
    const controller = new LiveLogController({
      access: async () => ({
        ...access(TICKET_ONE),
        transports: [
          {
            kind: "sse",
            method: "POST",
            path: "//evil.invalid/live/v3/logs",
          },
        ],
      }),
      fetch: vi.fn() as LiveLogFetch,
      maxConsecutiveFailures: 0,
      onRecord: vi.fn(),
      onFailure: failure,
    });

    await controller.start();

    expect(failure).toHaveBeenCalledWith(
      expect.objectContaining({ code: "protocol" }),
    );
  });

  it("pauses, resumes with a fresh ticket, and becomes permanently disposable", async () => {
    let acquisition = 0;
    const acquire = vi.fn((signal: AbortSignal): Promise<LiveLogAccess> => {
      acquisition += 1;
      if (acquisition === 2) {
        return Promise.resolve(access(TICKET_TWO));
      }
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    });
    const states: string[] = [];
    const controller = new LiveLogController({
      access: acquire,
      fetch: async () =>
        eventStreamResponse(
          completeEvent("checkpoint_complete"),
        ),
      onRecord: vi.fn(),
      onStateChange: (state) => states.push(state.kind),
    });

    expect(controller.running).toBe(false);
    const first = controller.start();
    expect(controller.running).toBe(true);
    expect(controller.start()).toBe(first);
    controller.pause();
    const resumed = controller.start();
    await resumed;

    expect(acquire).toHaveBeenCalledTimes(2);
    expect(states).toContain("paused");
    expect(controller.running).toBe(false);
    controller.dispose();
    await expect(controller.start()).rejects.toThrow("disposed");
  });

  it("can be paused during bounded retry backoff", async () => {
    vi.useFakeTimers();
    try {
      const controller = new LiveLogController({
        access: async () => access(TICKET_ONE),
        fetch: async () => new Response(null, { status: 503 }),
        maxConsecutiveFailures: 2,
        onRecord: vi.fn(),
      });

      const running = controller.start();
      await vi.advanceTimersByTimeAsync(0);
      controller.pause();
      await running;
      expect(controller.running).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("clears a failed run before allowing another start", async () => {
    const controller = new LiveLogController({
      access: async () => access(TICKET_ONE),
      onRecord: vi.fn(),
      onStateChange: () => {
        throw new Error("observer failed");
      },
    });

    await expect(controller.start()).rejects.toThrow("observer failed");
    expect(controller.running).toBe(false);
  });
});

describe("live-log SSE rejection", () => {
  it.each([
    [
      "HTTP failure",
      () => new Response(null, { status: 503 }),
      "transport",
      "returned 503",
    ],
    [
      "wrong content type",
      () => new Response("not SSE"),
      "protocol",
      "event stream",
    ],
    [
      "missing body",
      () =>
        new Response(null, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      "protocol",
      "no body",
    ],
    [
      "premature EOF",
      () => eventStreamResponse(""),
      "network",
      "before completion",
    ],
    [
      "invalid UTF-8",
      () => byteStreamResponse([new Uint8Array([0xff])]),
      "protocol",
      "not valid UTF-8",
    ],
    [
      "truncated UTF-8",
      () => byteStreamResponse([new Uint8Array([0xc3])]),
      "protocol",
      "within a UTF-8 character",
    ],
    [
      "oversized chunk",
      () => byteStreamResponse([new Uint8Array(1024 * 1024 + 1)]),
      "protocol",
      "chunk is too large",
    ],
    [
      "oversized buffer",
      () =>
        byteStreamResponse([
          new Uint8Array(600_000).fill(97),
          new Uint8Array(600_000).fill(97),
        ]),
      "protocol",
      "buffer is too large",
    ],
    [
      "oversized event",
      () =>
        eventStreamResponse(
          `data: ${"a".repeat(300_000)}\ndata: ${"b".repeat(300_000)}\n\n`,
        ),
      "protocol",
      "event is too large",
    ],
    [
      "record without checkpoint",
      () =>
        eventStreamResponse(
          logEvent("checkpoint", {}).replace("id: checkpoint\n", ""),
        ),
      "protocol",
      "no checkpoint",
    ],
    [
      "completion without checkpoint",
      () =>
        eventStreamResponse(
          "event: complete\ndata: {\"protocolVersion\":3}\n\n",
        ),
      "protocol",
      "no checkpoint",
    ],
    [
      "server error event",
      () =>
        eventStreamResponse(
          "event: error\ndata: {\"protocolVersion\":3,\"error\":\"internal_error\"}\n\n",
        ),
      "transport",
      "internal_error",
    ],
    [
      "unsupported event",
      () => eventStreamResponse("event: mystery\ndata: {}\n\n"),
      "protocol",
      "unsupported event",
    ],
    [
      "duplicate event field",
      () =>
        eventStreamResponse(
          "event: log\nevent: log\ndata: {}\n\n",
        ),
      "protocol",
      "repeats its type",
    ],
    [
      "invalid event ID",
      () => eventStreamResponse("id: bad\0id\nevent: log\ndata: {}\n\n"),
      "protocol",
      "invalid ID",
    ],
    [
      "duplicate retry field",
      () => eventStreamResponse("retry: 1000\nretry: 1000\n\n"),
      "protocol",
      "retry delay",
    ],
  ] as const)("rejects %s", async (_name, response, code, message) => {
    const failure = await failureFor(response());

    expect(failure).toEqual({ code, message: expect.stringContaining(message) });
  });

  it.each([
    [{ protocolVersion: 1 }, "protocol version"],
    [{ streamId: "not-a-uuid" }, "stream ID"],
    [{ sequence: "18446744073709551616" }, "sequence"],
    [{ part: -1 }, "part"],
    [{ emittedAtMs: 253_402_300_800_000 }, "timestamp"],
    [{ channel: "debug" }, "channel"],
    [{ dataBase64: "%%%" }, "data"],
    [{ dataBase64: "" }, "data"],
    [{ dataBase64: "Zg==" }, "data"],
    [{ dataBase64: "Zh" }, "data"],
    [{ dataBase64: "Zm9" }, "data"],
    [{ dataBase64: "A".repeat(65_537) }, "data"],
    [{ extra: true }, "unexpected fields"],
  ])("rejects malformed record fields %#", async (overrides, message) => {
    const failure = await failureFor(eventStreamResponse(logEvent("checkpoint", overrides)));

    expect(failure).toEqual({
      code: "protocol",
      message: expect.stringContaining(message),
    });
  });

  it.each(["Build\tstep", "Build\u202estep"]) (
    "rejects an unsafe log group name %#",
    async (name) => {
      const failure = await failureFor(
        eventStreamResponse(
          recordEvent("checkpoint", {
            protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
            streamId: STREAM_ID,
            sequence: "1",
            emittedAtMs: 1_777_890_010_000,
            type: "group_started",
            group: {
              id: "phase/1",
              parentId: null,
              name,
              kind: "step",
              ordinal: 1,
            },
          }),
        ),
      );

      expect(failure).toEqual({
        code: "protocol",
        message: expect.stringContaining("group name"),
      });
    },
  );

  it.each([
    ["not JSON", "not valid JSON"],
    ["[]", "not an object"],
  ])("rejects a log document that is %s", async (data, message) => {
    const failure = await failureFor(
      eventStreamResponse(`id: checkpoint\nevent: log\ndata: ${data}\n\n`),
    );

    expect(failure.message).toContain(message);
  });

  it("ignores extension fields in SSE framing itself", async () => {
    const controller = new LiveLogController({
      access: async () => access(TICKET_ONE),
      fetch: async () =>
        eventStreamResponse(
          `extension: ignored\n${completeEvent("checkpoint_complete")}`,
        ),
      onRecord: vi.fn(),
    });

    await controller.start();
  });
});

function access(ticket: string): LiveLogAccess {
  return {
    protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
    ticket,
    expiresAtMs: Date.now() + 60_000,
    logsOrigin: "https://logs.example",
    transports: [{ kind: "sse", method: "POST", path: "/live/v3/logs" }],
  };
}

function logEvent(
  checkpoint: string,
  overrides: Readonly<Record<string, unknown>> = {},
): string {
  const { text = "line", ...fields } = overrides;
  const record = {
    protocolVersion: LIVE_LOG_PROTOCOL_VERSION,
    streamId: STREAM_ID,
    sequence: "1",
    emittedAtMs: 1_777_890_010_000,
    type: "output",
    groupId: "phase/1",
    channel: "stdout",
    part: 0,
    dataBase64: encodeText(typeof text === "string" ? text : "line"),
    ...fields,
  };
  return recordEvent(checkpoint, record);
}

function encodeText(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeText(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

function recordEvent(checkpoint: string, record: unknown): string {
  return `id: ${checkpoint}\nevent: log\ndata: ${JSON.stringify(record)}\n\n`;
}

function completeEvent(checkpoint: string): string {
  return `id: ${checkpoint}\nevent: complete\ndata: {"protocolVersion":3}\n\n`;
}

function eventStreamResponse(
  value: string,
  cutPoints: readonly number[] = [],
): Response {
  const bytes = new TextEncoder().encode(value);
  const points = [...cutPoints, bytes.length]
    .filter((point) => point > 0 && point <= bytes.length)
    .sort((left, right) => left - right);
  let offset = 0;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const point of points) {
        if (point > offset) {
          controller.enqueue(bytes.slice(offset, point));
          offset = point;
        }
      }
      controller.close();
    },
  });
  return new Response(body, {
    headers: { "Content-Type": "text/event-stream; charset=utf-8" },
  });
}

function byteStreamResponse(chunks: readonly Uint8Array[]): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      chunks.forEach((chunk) => controller.enqueue(chunk));
      controller.close();
    },
  });
  return new Response(body, {
    headers: { "Content-Type": "text/event-stream; charset=utf-8" },
  });
}

async function failureFor(response: Response): Promise<LiveLogFailure> {
  let failure: LiveLogFailure | undefined;
  const controller = new LiveLogController({
    access: async () => access(TICKET_ONE),
    fetch: async () => response,
    maxConsecutiveFailures: 0,
    onRecord: vi.fn(),
    onFailure: (selected) => {
      failure = selected;
    },
  });

  await controller.start();
  if (failure === undefined) {
    throw new Error("the live-log controller did not report failure");
  }
  return failure;
}
