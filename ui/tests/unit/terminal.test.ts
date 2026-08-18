import { describe, expect, it } from "vitest";
import type { LiveLogOutputRecord } from "../../src/logs/sse";
import { TerminalTranscript } from "../../src/logs/terminal";

const STREAM_ID = "00000000-0000-4000-8000-000000000005";

describe("terminal transcript", () => {
  it("renders SGR styles without exposing escape syntax", () => {
    const lines = transcript("\u001b[1;31merror\u001b[0m plain\n");

    expect(lines).toHaveLength(1);
    expect(lines[0]?.text).toBe("error plain");
    expect(lines[0]?.spans[0]).toMatchObject({
      text: "error",
      style: { bold: true, foreground: { kind: "palette", index: 1 } },
    });
    expect(lines[0]?.spans[1]).toMatchObject({
      text: " plain",
      style: { bold: false, foreground: null },
    });
  });

  it("preserves UTF-8 and terminal state across every byte boundary", () => {
    const bytes = new TextEncoder().encode("\u001b[38:2::12:34:56m café 👩‍💻\u001b[0m\n");
    const decoder = new TerminalTranscript();
    const lines = [];
    for (let part = 0; part < bytes.length; part += 1) {
      lines.push(...decoder.push(output(bytes.slice(part, part + 1), part)));
    }

    expect(lines).toHaveLength(1);
    expect(lines[0]?.text).toBe(" café 👩‍💻");
    expect(lines[0]?.spans[0]?.style.foreground).toEqual({
      kind: "rgb", red: 12, green: 34, blue: 56,
    });
  });

  it("projects carriage-return progress and erase-line controls", () => {
    expect(transcript("10%\r\u001b[2K100%\n")[0]?.text).toBe("100%");
    expect(transcript("abc\bZ\n")[0]?.text).toBe("abZ");
    expect(transcript("a\tb\n")[0]?.text).toBe("a       b");
  });

  it("projects an in-progress row and replaces it across streamed updates", () => {
    const decoder = new TerminalTranscript();
    expect(decoder.push(output(new TextEncoder().encode("10%"), 0))).toEqual([]);
    expect(decoder.currentLine()).toMatchObject({ key: "7:0:pending", number: "7", text: "10%" });

    decoder.push(output(new TextEncoder().encode("\r\u001b[2K100%"), 1));
    expect(decoder.currentLine()).toMatchObject({ key: "7:0:pending", number: "7", text: "100%" });

    const completed = decoder.push(output(new TextEncoder().encode("\n"), 2));
    expect(completed[0]).toMatchObject({ key: "7:0:1", number: "7", text: "100%" });
    expect(decoder.currentLine()).toBeNull();
  });

  it("supports safe OSC 8 links and makes active schemes inert", () => {
    const safe = transcript("\u001b]8;;https://example.com/build\u0007build\u001b]8;;\u0007\n")[0];
    const unsafe = transcript("\u001b]8;;javascript:alert(1)\u0007click\u001b]8;;\u0007\n")[0];

    expect(safe?.spans[0]).toMatchObject({ text: "build", href: "https://example.com/build" });
    expect(unsafe?.spans[0]).toMatchObject({ text: "click", href: null });
  });

  it("localizes malformed UTF-8 and exposes bidi formatting controls safely", () => {
    const decoder = new TerminalTranscript();
    const lines = decoder.push(output(Uint8Array.from([0x66, 0x80, 0x6f, 0xe2, 0x80, 0xae, 0x0a]), 0));

    expect(lines[0]?.text).toBe("f�o⟦RLO⟧");
  });

  it("bounds and ignores unterminated control strings without losing later output", () => {
    const decoder = new TerminalTranscript();
    decoder.push(output(new TextEncoder().encode(`\u001b]52;;${"x".repeat(5_000)}\u0007`), 0));
    const lines = decoder.push(output(new TextEncoder().encode("visible\n"), 1));

    expect(lines[0]?.text).toBe("visible");
  });

  it("supports the complete SGR attribute and palette reset surface", () => {
    const styled = transcript("\u001b[1;2;3;4;5;7;8;9;53;97;104mX\u001b[22;23;24;25;27;28;29;55;39;49mY\n")[0];

    expect(styled?.spans[0]?.style).toMatchObject({
      bold: true,
      dim: true,
      italic: true,
      underline: "single",
      blink: true,
      inverse: true,
      conceal: true,
      strike: true,
      overline: true,
      foreground: { kind: "palette", index: 15 },
      background: { kind: "palette", index: 12 },
    });
    expect(styled?.spans[1]?.style).toMatchObject({
      bold: false,
      dim: false,
      italic: false,
      underline: "none",
      blink: false,
      inverse: false,
      conceal: false,
      strike: false,
      overline: false,
      foreground: null,
      background: null,
    });

    expect(transcript("\u001b[6;21;30;40mX\n")[0]?.spans[0]?.style).toMatchObject({
      blink: true,
      underline: "double",
      foreground: { kind: "palette", index: 0 },
      background: { kind: "palette", index: 0 },
    });
  });

  it("supports semicolon and colon extended colors and underline styles", () => {
    const lines = transcript([
      "\u001b[38;5;200;48;2;1;2;3;58;5;9mA",
      "\u001b[4:0m0\u001b[4:2m2\u001b[4:3m3\u001b[4:4m4\u001b[4:5m5\u001b[4:9m1",
      "\u001b[38:2:0:4:5:6mB\u001b[59mC\n",
    ].join(""))[0];

    expect(lines?.spans[0]?.style).toMatchObject({
      foreground: { kind: "palette", index: 200 },
      background: { kind: "rgb", red: 1, green: 2, blue: 3 },
      underlineColor: { kind: "palette", index: 9 },
    });
    expect(lines?.text).toBe("A023451BC");
    expect(lines?.spans.map((span) => span.style.underline)).toContain("curly");
    expect(lines?.spans.map((span) => span.style.underline)).toContain("dotted");
    expect(lines?.spans.map((span) => span.style.underline)).toContain("dashed");
    expect(lines?.spans.at(-1)?.style.underlineColor).toBeNull();
  });

  it("ignores malformed SGR parameters without consuming later attributes", () => {
    const line = transcript("\u001b[38;5;999;1mA\u001b[48:2:1:2mB\u001b[9999999mC\n")[0];

    expect(line?.text).toBe("ABC");
    expect(line?.spans[0]?.style.foreground).toBeNull();
    expect(line?.spans[0]?.style.bold).toBe(true);
    expect(line?.spans[0]?.style.background).toBeNull();
  });

  it("applies horizontal cursor editing, insertion, deletion, and erasure", () => {
    expect(transcript("abc\u001b[2DZ\n")[0]?.text).toBe("aZc");
    expect(transcript("abc\u001b[1GZ\n")[0]?.text).toBe("Zbc");
    expect(transcript("a\u001b[3Cb\n")[0]?.text).toBe("a   b");
    expect(transcript("abcd\r\u001b[2C\u001b[@Z\n")[0]?.text).toBe("abZcd");
    expect(transcript("abcd\r\u001b[2C\u001b[P\n")[0]?.text).toBe("abd");
    expect(transcript("abcd\r\u001b[2C\u001b[2X\n")[0]?.text).toBe("ab  ");
    expect(transcript("abcd\r\u001b[2C\u001b[1K\n")[0]?.text).toBe("   d");
    expect(transcript("abcd\r\u001b[2C\u001b[K\n")[0]?.text).toBe("ab");
    expect(transcript("abcd\u001b[2JZ\n")[0]?.text).toBe("Z");
  });

  it("saves, restores, and resets the terminal cursor", () => {
    expect(transcript("ab\u001b7cd\u001b8Z\n")[0]?.text).toBe("abZd");
    expect(transcript("ab\u001b[s\u001b[2CZ\u001b[uY\n")[0]?.text).toBe("abY Z");
    expect(transcript("before\u001bcafter\n")[0]?.text).toBe("after");
    expect(transcript("a\u001b?b\n")[0]?.text).toBe("ab");
  });

  it("discards OSC, DCS, SOS, PM, and APC payloads with either terminator", () => {
    expect(transcript("a\u001bPsecret\u001b\\b\u001bXsecret\u009cc\u001b^secret\u001b\\d\u001b_secret\u001b\\e\n")[0]?.text)
      .toBe("abcde");
    expect(transcript("\u001b]title\u001bx\u001b\\visible\n")[0]?.text).toBe("visible");
    expect(transcript("\u001b]8;missing\u0007x\n")[0]?.spans[0]?.href).toBeNull();
    expect(transcript("\u001b]9;ignored\u0007x\n")[0]?.text).toBe("x");
  });

  it("supports 8-bit terminal controls without confusing UTF-8 continuation bytes", () => {
    const bytes = Uint8Array.from([
      0x9b, 0x33, 0x31, 0x6d, 0x58, // CSI 31 m, X
      0xd0, 0x9b, // U+041B, whose second byte is also the 8-bit CSI value
      0x9d, 0x38, 0x3b, 0x3b, ...new TextEncoder().encode("https://example.com"), 0x9c,
      0x59,
      0x90, 0x78, 0x9c,
      0x0a,
    ]);
    const line = new TerminalTranscript().push(output(bytes, 0))[0];

    expect(line?.text).toBe("XЛY");
    expect(line?.spans[0]?.style.foreground).toEqual({ kind: "palette", index: 1 });
    expect(line?.spans.at(-1)?.href).toBe("https://example.com");
  });

  it("renders otherwise active C0 controls visibly while ignoring NUL and bell", () => {
    const bytes = Uint8Array.from([0, 7, 1, 0x7f, 0x0a]);
    expect(new TerminalTranscript().push(output(bytes, 0))[0]?.text).toBe("⟦␁⟧⟦DEL⟧");
  });

  it("combines Unicode marks and replaces each malformed UTF-8 subsequence locally", () => {
    expect(transcript("e\u0301\n")[0]?.spans[0]?.text).toBe("é");

    const invalid = Uint8Array.from([
      0xe2, 0x41, // interrupted sequence, then the ASCII byte is retried
      0xe0, 0x80, 0x80, // overlong
      0xed, 0xa0, 0x80, // surrogate
      0xf4, 0x90, 0x80, 0x80, // beyond U+10FFFF
      0xff, 0x0a,
    ]);
    expect(new TerminalTranscript().push(output(invalid, 0))[0]?.text).toBe("�A����");
  });

  it("flushes incomplete Unicode and partial lines deterministically on finish", () => {
    const decoder = new TerminalTranscript();
    expect(decoder.push(output(Uint8Array.from([0xf0, 0x9f]), 0))).toEqual([]);
    const lines = decoder.finish();

    expect(lines[0]).toMatchObject({
      key: "7:0:1",
      number: "7",
      channel: "stdout",
      text: "�",
    });
    expect(decoder.finish()).toEqual([]);
  });

  it("numbers multiple physical lines from one record and preserves the first origin", () => {
    const decoder = new TerminalTranscript();
    const lines = decoder.push(output(new TextEncoder().encode("one\ntwo\n"), 3));

    expect(lines.map((line) => [line.key, line.number, line.sourceSequence, line.emittedAtMs])).toEqual([
      ["7:3:1", "7", "7", 1_777_890_010_003],
      ["7:3:2", "7.2", "7", 1_777_890_010_003],
    ]);
  });

  it("discards malformed and overlong CSI sequences", () => {
    const decoder = new TerminalTranscript();
    decoder.push(output(new TextEncoder().encode(`\u001b[${"1".repeat(5_000)}`), 0));
    const lines = decoder.push(output(Uint8Array.from([0x6d, 0x1b, 0x5b, 0x80, 0x41, 0x6f, 0x6b, 0x0a]), 1));

    expect(lines[0]?.text).toBe("Aok");
  });

  it("bounds adversarial cursor movement and marks truncated rows", () => {
    const line = transcript("prefix\u001b[999999Cignored\n")[0];

    expect(line?.text.length).toBeLessThan(66_000);
    expect(line?.text.endsWith("⟦terminal row truncated⟧")).toBe(true);
  });
});

function transcript(value: string) {
  return new TerminalTranscript().push(output(new TextEncoder().encode(value), 0));
}

function output(data: Uint8Array, part: number): LiveLogOutputRecord {
  return {
    type: "output",
    streamId: STREAM_ID,
    sequence: "7",
    emittedAtMs: 1_777_890_010_000 + part,
    groupId: "phase/1",
    channel: "stdout",
    part,
    data,
  };
}
