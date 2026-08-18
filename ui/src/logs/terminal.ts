import type { LiveLogChannel, LiveLogOutputRecord } from "./sse";

const MAX_CONTROL_SEQUENCE_BYTES = 4_096;
const MAX_TERMINAL_COLUMNS = 65_536;
const TRUNCATION_MARKER = "⟦terminal row truncated⟧";
const CONTROL_LABELS = new Map<number, string>([
  [0x061c, "ALM"], [0x200e, "LRM"], [0x200f, "RLM"],
  [0x202a, "LRE"], [0x202b, "RLE"], [0x202c, "PDF"],
  [0x202d, "LRO"], [0x202e, "RLO"], [0x2066, "LRI"],
  [0x2067, "RLI"], [0x2068, "FSI"], [0x2069, "PDI"],
]);

export type TerminalColor =
  | { readonly kind: "palette"; readonly index: number }
  | { readonly kind: "rgb"; readonly red: number; readonly green: number; readonly blue: number };

export type TerminalUnderline = "none" | "single" | "double" | "curly" | "dotted" | "dashed";

export interface TerminalTextStyle {
  readonly bold: boolean;
  readonly dim: boolean;
  readonly italic: boolean;
  readonly underline: TerminalUnderline;
  readonly blink: boolean;
  readonly inverse: boolean;
  readonly conceal: boolean;
  readonly strike: boolean;
  readonly overline: boolean;
  readonly foreground: TerminalColor | null;
  readonly background: TerminalColor | null;
  readonly underlineColor: TerminalColor | null;
}

export interface TerminalSpan {
  readonly text: string;
  readonly style: TerminalTextStyle;
  readonly href: string | null;
}

export interface TerminalLine {
  readonly key: string;
  readonly number: string;
  readonly emittedAtMs: number;
  readonly channel: LiveLogChannel;
  readonly sourceSequence: string;
  readonly spans: readonly TerminalSpan[];
  readonly text: string;
}

interface Cell {
  readonly text: string;
  readonly style: TerminalTextStyle;
  readonly href: string | null;
}

interface LineOrigin {
  readonly sequence: string;
  readonly part: number;
  readonly emittedAtMs: number;
  readonly channel: LiveLogChannel;
}

type ParserState = "ground" | "escape" | "csi" | "osc" | "osc_escape" | "string" | "string_escape";

const DEFAULT_STYLE: TerminalTextStyle = Object.freeze({
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
  underlineColor: null,
});

/** Incrementally projects untrusted terminal bytes into a safe append-only transcript. */
export class TerminalTranscript {
  readonly #utf8 = new Utf8Decoder((codePoint) => this.#writeCodePoint(codePoint));
  readonly #sequenceLineCounts = new Map<string, number>();
  #state: ParserState = "ground";
  #control: number[] = [];
  #controlOverflow = false;
  #style = DEFAULT_STYLE;
  #href: string | null = null;
  #cells: Cell[] = [];
  #lineTruncated = false;
  #cursor = 0;
  #savedCursor = 0;
  #origin: LineOrigin | null = null;
  #candidateOrigin: LineOrigin | null = null;
  #activeRecord: LiveLogOutputRecord | null = null;
  #emittedAtMs = 0;
  #completed: TerminalLine[] = [];

  push(record: LiveLogOutputRecord): readonly TerminalLine[] {
    this.#activeRecord = record;
    this.#emittedAtMs = record.emittedAtMs;
    if (this.#origin === null && this.#candidateOrigin === null && record.data.length > 0) {
      this.#candidateOrigin = originFrom(record);
    }
    for (const byte of record.data) this.#byte(byte);
    this.#activeRecord = null;
    return this.#takeCompleted();
  }

  /** Returns the current mutable terminal row for live rendering, if one exists. */
  currentLine(): TerminalLine | null {
    if (this.#origin === null) return null;
    const count = (this.#sequenceLineCounts.get(this.#origin.sequence) ?? 0) + 1;
    return this.#projectLine(this.#origin, count, true);
  }

  finish(): readonly TerminalLine[] {
    this.#utf8.finish();
    this.#state = "ground";
    this.#control = [];
    this.#controlOverflow = false;
    if (this.#cells.length > 0 || this.#origin !== null) this.#completeLine();
    this.#candidateOrigin = null;
    this.#style = DEFAULT_STYLE;
    this.#href = null;
    return this.#takeCompleted();
  }

  #takeCompleted(): readonly TerminalLine[] {
    const completed = this.#completed;
    this.#completed = [];
    return completed;
  }

  #byte(byte: number): void {
    switch (this.#state) {
      case "ground": this.#ground(byte); return;
      case "escape": this.#escape(byte); return;
      case "csi": this.#collectCsi(byte); return;
      case "osc": this.#collectOsc(byte); return;
      case "osc_escape":
        if (byte === 0x5c) this.#finishOsc();
        else { this.#appendControl(0x1b); this.#appendControl(byte); this.#state = "osc"; }
        return;
      case "string":
        if (byte === 0x1b) this.#state = "string_escape";
        else if (byte === 0x9c) this.#discardControl();
        else this.#appendControl(byte);
        return;
      case "string_escape":
        if (byte === 0x5c) this.#discardControl();
        else { this.#appendControl(byte); this.#state = "string"; }
        return;
    }
  }

  #ground(byte: number): void {
    if (!this.#utf8.hasPendingSequence) {
      if (byte === 0x9b) { this.#beginControl("csi"); return; }
      if (byte === 0x9d) { this.#beginControl("osc"); return; }
      if (byte === 0x90 || byte === 0x98 || byte === 0x9e || byte === 0x9f) { this.#beginControl("string"); return; }
      if (byte === 0x9c) return;
    }
    if (byte === 0x1b) { this.#utf8.finish(); this.#state = "escape"; return; }
    if (byte === 0x0a) { this.#utf8.finish(); this.#ensureOrigin(); this.#completeLine(); return; }
    if (byte === 0x0d) { this.#utf8.finish(); this.#ensureOrigin(); this.#cursor = 0; return; }
    if (byte === 0x08) { this.#utf8.finish(); this.#ensureOrigin(); this.#cursor = Math.max(0, this.#cursor - 1); return; }
    if (byte === 0x09) { this.#utf8.finish(); this.#ensureOrigin(); this.#moveCursor(Math.floor(this.#cursor / 8 + 1) * 8); return; }
    if (byte === 0x00 || byte === 0x07) return;
    if (byte < 0x20 || byte === 0x7f) {
      this.#utf8.finish();
      this.#writeText(`⟦${controlName(byte)}⟧`);
      return;
    }
    this.#utf8.push(byte);
  }

  #escape(byte: number): void {
    if (byte === 0x5b) { this.#beginControl("csi"); return; }
    if (byte === 0x5d) { this.#beginControl("osc"); return; }
    if (byte === 0x50 || byte === 0x58 || byte === 0x5e || byte === 0x5f) { this.#beginControl("string"); return; }
    if (byte === 0x37) { this.#savedCursor = this.#cursor; this.#state = "ground"; return; }
    if (byte === 0x38) { this.#moveCursor(this.#savedCursor); this.#state = "ground"; return; }
    if (byte === 0x63) { this.#style = DEFAULT_STYLE; this.#href = null; this.#cells = []; this.#lineTruncated = false; this.#cursor = 0; this.#state = "ground"; return; }
    this.#state = "ground";
  }

  #beginControl(state: ParserState): void {
    this.#control = [];
    this.#controlOverflow = false;
    this.#state = state;
  }

  #appendControl(byte: number): void {
    if (this.#controlOverflow) return;
    if (this.#control.length >= MAX_CONTROL_SEQUENCE_BYTES) {
      this.#control = [];
      this.#controlOverflow = true;
      return;
    }
    this.#control.push(byte);
  }

  #discardControl(): void {
    this.#control = [];
    this.#controlOverflow = false;
    this.#state = "ground";
  }

  #collectCsi(byte: number): void {
    if (byte >= 0x40 && byte <= 0x7e) {
      const overflowed = this.#controlOverflow;
      const parameters = ascii(this.#control);
      this.#control = [];
      this.#controlOverflow = false;
      this.#state = "ground";
      if (!overflowed) this.#csi(parameters, String.fromCharCode(byte));
      return;
    }
    if (byte < 0x20 || byte > 0x3f) { this.#discardControl(); return; }
    this.#appendControl(byte);
  }

  #collectOsc(byte: number): void {
    if (byte === 0x07 || byte === 0x9c) { this.#finishOsc(); return; }
    if (byte === 0x1b) { this.#state = "osc_escape"; return; }
    this.#appendControl(byte);
  }

  #finishOsc(): void {
    const overflowed = this.#controlOverflow;
    const value = decodeUtf8(this.#control);
    this.#discardControl();
    if (overflowed) return;
    const first = value.indexOf(";");
    if (first < 0 || value.slice(0, first) !== "8") return;
    const second = value.indexOf(";", first + 1);
    if (second < 0) return;
    const candidate = value.slice(second + 1);
    this.#href = candidate === "" ? null : safeTerminalHref(candidate);
  }

  #csi(raw: string, final: string): void {
    const values = csiNumbers(raw);
    const amount = Math.max(1, values[0] ?? 1);
    switch (final) {
      case "m": this.#sgr(raw); break;
      case "G": case "`": this.#moveCursor(amount - 1); break;
      case "C": case "a": this.#moveCursor(this.#cursor + amount); break;
      case "D": this.#cursor = Math.max(0, this.#cursor - amount); break;
      case "@": this.#insertCells(amount); break;
      case "P": this.#cells.splice(this.#cursor, amount); break;
      case "X": this.#eraseCells(this.#cursor, amount); break;
      case "K": this.#eraseLine(values[0] ?? 0); break;
      case "J": if ((values[0] ?? 0) === 2) { this.#cells = []; this.#lineTruncated = false; this.#cursor = 0; } break;
      case "s": this.#savedCursor = this.#cursor; break;
      case "u": this.#moveCursor(this.#savedCursor); break;
      default: break;
    }
  }

  #sgr(raw: string): void {
    const tokens = raw === "" ? ["0"] : raw.split(";");
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index] ?? "";
      const colon = token.split(":").map(numberParameter);
      const code = colon[0] ?? 0;
      if (code === 4 && colon.length > 1) {
        this.#setStyle({ underline: underlineKind(colon[1] ?? 1) });
        continue;
      }
      if (code === 38 || code === 48 || code === 58) {
        const inline = colon.length > 1
          ? colon.slice(1)
          : tokens.slice(index + 1, index + 5).map(numberParameter);
        const parsed = extendedColor(inline);
        if (parsed !== null) {
          const field = code === 38 ? "foreground" : code === 48 ? "background" : "underlineColor";
          this.#setStyle({ [field]: parsed.color });
          if (colon.length === 1) index += parsed.consumed;
        }
        continue;
      }
      this.#simpleSgr(code);
    }
  }

  #simpleSgr(code: number): void {
    if (code === 0) { this.#style = DEFAULT_STYLE; return; }
    if (code === 1) this.#setStyle({ bold: true });
    else if (code === 2) this.#setStyle({ dim: true });
    else if (code === 3) this.#setStyle({ italic: true });
    else if (code === 4) this.#setStyle({ underline: "single" });
    else if (code === 5 || code === 6) this.#setStyle({ blink: true });
    else if (code === 7) this.#setStyle({ inverse: true });
    else if (code === 8) this.#setStyle({ conceal: true });
    else if (code === 9) this.#setStyle({ strike: true });
    else if (code === 21) this.#setStyle({ underline: "double" });
    else if (code === 22) this.#setStyle({ bold: false, dim: false });
    else if (code === 23) this.#setStyle({ italic: false });
    else if (code === 24) this.#setStyle({ underline: "none" });
    else if (code === 25) this.#setStyle({ blink: false });
    else if (code === 27) this.#setStyle({ inverse: false });
    else if (code === 28) this.#setStyle({ conceal: false });
    else if (code === 29) this.#setStyle({ strike: false });
    else if (code >= 30 && code <= 37) this.#setStyle({ foreground: palette(code - 30) });
    else if (code === 39) this.#setStyle({ foreground: null });
    else if (code >= 40 && code <= 47) this.#setStyle({ background: palette(code - 40) });
    else if (code === 49) this.#setStyle({ background: null });
    else if (code === 53) this.#setStyle({ overline: true });
    else if (code === 55) this.#setStyle({ overline: false });
    else if (code === 59) this.#setStyle({ underlineColor: null });
    else if (code >= 90 && code <= 97) this.#setStyle({ foreground: palette(code - 90 + 8) });
    else if (code >= 100 && code <= 107) this.#setStyle({ background: palette(code - 100 + 8) });
  }

  #setStyle(patch: Partial<TerminalTextStyle>): void {
    this.#style = Object.freeze({ ...this.#style, ...patch });
  }

  #writeCodePoint(codePoint: number): void {
    const label = CONTROL_LABELS.get(codePoint);
    this.#writeText(label === undefined ? String.fromCodePoint(codePoint) : `⟦${label}⟧`);
  }

  #writeText(text: string): void {
    this.#ensureOrigin();
    const cell = { text, style: this.#style, href: this.#href };
    if (text.charCodeAt(0) >= 0x0300 && isUnicodeMark(text) && this.#cursor > 0) {
      const previous = this.#cells[this.#cursor - 1];
      if (previous !== undefined) this.#cells[this.#cursor - 1] = { ...previous, text: previous.text + text };
      return;
    }
    this.#moveCursor(this.#cursor);
    if (this.#cursor >= MAX_TERMINAL_COLUMNS) {
      this.#lineTruncated = true;
      return;
    }
    this.#cells[this.#cursor] = cell;
    this.#cursor += 1;
  }

  #ensureOrigin(): void {
    if (this.#origin !== null) return;
    const record = this.#activeRecord;
    if (this.#candidateOrigin !== null) this.#origin = this.#candidateOrigin;
    else if (record !== null) this.#origin = originFrom(record);
  }

  #moveCursor(position: number): void {
    this.#ensureOrigin();
    const bounded = Math.min(position, MAX_TERMINAL_COLUMNS);
    while (this.#cells.length < bounded) this.#cells.push({ text: " ", style: this.#style, href: this.#href });
    this.#cursor = bounded;
  }

  #insertCells(amount: number): void {
    this.#ensureOrigin();
    const available = Math.max(0, MAX_TERMINAL_COLUMNS - this.#cursor);
    const retained = Math.min(amount, available);
    if (amount > retained || this.#cells.length + retained > MAX_TERMINAL_COLUMNS) this.#lineTruncated = true;
    const blanks = Array.from({ length: retained }, () => ({ text: " ", style: this.#style, href: this.#href }));
    this.#cells.splice(this.#cursor, 0, ...blanks);
    if (this.#cells.length > MAX_TERMINAL_COLUMNS) this.#cells.length = MAX_TERMINAL_COLUMNS;
  }

  #eraseCells(start: number, amount: number): void {
    for (let offset = 0; offset < amount && start + offset < this.#cells.length; offset += 1) {
      this.#cells[start + offset] = { text: " ", style: this.#style, href: this.#href };
    }
  }

  #eraseLine(mode: number): void {
    if (mode === 2) { this.#cells = []; this.#lineTruncated = false; this.#cursor = 0; }
    else if (mode === 1) this.#eraseCells(0, this.#cursor + 1);
    else { this.#cells.splice(this.#cursor); this.#lineTruncated = false; }
  }

  #completeLine(): void {
    const origin = this.#origin;
    if (origin === null) return;
    const count = (this.#sequenceLineCounts.get(origin.sequence) ?? 0) + 1;
    this.#sequenceLineCounts.set(origin.sequence, count);
    this.#completed.push(this.#projectLine(origin, count, false));
    this.#cells = [];
    this.#lineTruncated = false;
    this.#cursor = 0;
    this.#origin = null;
    this.#candidateOrigin = null;
  }

  #projectLine(origin: LineOrigin, count: number, pending: boolean): TerminalLine {
    const spans = coalesce(this.#cells);
    if (this.#lineTruncated) spans.push({ text: TRUNCATION_MARKER, style: DEFAULT_STYLE, href: null });
    return {
      key: `${origin.sequence}:${origin.part}:${pending ? "pending" : count}`,
      number: count === 1 ? origin.sequence : `${origin.sequence}.${count}`,
      emittedAtMs: this.#emittedAtMs || origin.emittedAtMs,
      channel: origin.channel,
      sourceSequence: origin.sequence,
      spans,
      text: spans.map((span) => span.text).join(""),
    };
  }

}

let unicodeMarkPattern: RegExp | undefined;

function isUnicodeMark(text: string): boolean {
  // Construct lazily so the embedded SSR engine never has to parse Unicode
  // property-escape syntax that is used only by the browser terminal stream.
  unicodeMarkPattern ??= new RegExp("^\\p{Mark}$", "u");
  return unicodeMarkPattern.test(text);
}

function originFrom(record: LiveLogOutputRecord): LineOrigin {
  return { sequence: record.sequence, part: record.part, emittedAtMs: record.emittedAtMs, channel: record.channel };
}

function coalesce(cells: readonly Cell[]): TerminalSpan[] {
  const spans: TerminalSpan[] = [];
  for (const cell of cells) {
    const previous = spans[spans.length - 1];
    if (previous !== undefined && previous.style === cell.style && previous.href === cell.href) {
      spans[spans.length - 1] = { ...previous, text: previous.text + cell.text };
    } else spans.push({ text: cell.text, style: cell.style, href: cell.href });
  }
  return spans;
}

function csiNumbers(raw: string): number[] {
  return raw.replace(/^[?<>=!]+/u, "").split(";").map(numberParameter);
}

function numberParameter(value: string): number {
  if (!/^[0-9]{1,6}$/u.test(value)) return value === "" ? 0 : -1;
  return Number(value);
}

function underlineKind(value: number): TerminalUnderline {
  return value === 0 ? "none" : value === 2 ? "double" : value === 3 ? "curly" : value === 4 ? "dotted" : value === 5 ? "dashed" : "single";
}

function extendedColor(values: readonly number[]): { readonly color: TerminalColor; readonly consumed: number } | null {
  if (values[0] === 5 && validByte(values[1])) return { color: palette(values[1] as number), consumed: 2 };
  if (values[0] === 2) {
    const offset = values.length >= 5 && values[1] === 0 ? 2 : 1;
    const red = values[offset]; const green = values[offset + 1]; const blue = values[offset + 2];
    if (validByte(red) && validByte(green) && validByte(blue)) {
      return { color: { kind: "rgb", red: red as number, green: green as number, blue: blue as number }, consumed: offset + 2 };
    }
  }
  return null;
}

function validByte(value: number | undefined): boolean {
  return value !== undefined && Number.isInteger(value) && value >= 0 && value <= 255;
}

function palette(index: number): TerminalColor {
  return { kind: "palette", index };
}

function safeTerminalHref(value: string): string | null {
  if (value.length > 2_048 || /[\u0000-\u0020\u007f]/u.test(value)) return null;
  return /^https?:\/\//iu.test(value) ? value : null;
}

function ascii(bytes: readonly number[]): string {
  return String.fromCharCode(...bytes);
}

function controlName(byte: number): string {
  if (byte === 0x7f) return "DEL";
  return byte >= 0 && byte < 0x20 ? String.fromCharCode(0x2400 + byte) : `U+${byte.toString(16).toUpperCase().padStart(4, "0")}`;
}

function decodeUtf8(bytes: readonly number[]): string {
  let value = "";
  const decoder = new Utf8Decoder((codePoint) => { value += String.fromCodePoint(codePoint); });
  for (const byte of bytes) decoder.push(byte);
  decoder.finish();
  return value;
}

class Utf8Decoder {
  readonly #emit: (codePoint: number) => void;
  #remaining = 0;
  #codePoint = 0;
  #minimum = 0;

  constructor(emit: (codePoint: number) => void) { this.#emit = emit; }

  get hasPendingSequence(): boolean { return this.#remaining !== 0; }

  push(byte: number): void {
    if (this.#remaining === 0) {
      if (byte <= 0x7f) this.#emit(byte);
      else if (byte >= 0xc2 && byte <= 0xdf) this.#start(byte & 0x1f, 1, 0x80);
      else if (byte >= 0xe0 && byte <= 0xef) this.#start(byte & 0x0f, 2, 0x800);
      else if (byte >= 0xf0 && byte <= 0xf4) this.#start(byte & 0x07, 3, 0x10000);
      else this.#emit(0xfffd);
      return;
    }
    if (byte < 0x80 || byte > 0xbf) {
      this.#emit(0xfffd);
      this.#remaining = 0;
      this.push(byte);
      return;
    }
    this.#codePoint = (this.#codePoint << 6) | (byte & 0x3f);
    this.#remaining -= 1;
    if (this.#remaining !== 0) return;
    const codePoint = this.#codePoint;
    if (codePoint < this.#minimum || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) this.#emit(0xfffd);
    else this.#emit(codePoint);
  }

  finish(): void {
    if (this.#remaining !== 0) this.#emit(0xfffd);
    this.#remaining = 0;
  }

  #start(codePoint: number, remaining: number, minimum: number): void {
    this.#codePoint = codePoint;
    this.#remaining = remaining;
    this.#minimum = minimum;
  }
}
