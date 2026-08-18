import type { TerminalLine } from "./terminal";

export type TerminalLineElementFactory = (line: TerminalLine) => HTMLElement;

/** Owns a hydrated output element and incrementally updates its terminal rows. */
export class TerminalDomRenderer {
  readonly #host: HTMLElement;
  readonly #createLine: TerminalLineElementFactory;
  #rendered: TerminalLine[] = [];
  #source: readonly TerminalLine[] | null = null;

  constructor(host: HTMLElement, createLine: TerminalLineElementFactory) {
    this.#host = host;
    this.#createLine = createLine;
  }

  sync(lines: readonly TerminalLine[]): void {
    if (lines === this.#source && lines.length >= this.#rendered.length) {
      this.#append(lines, this.#rendered.length);
      return;
    }

    let unchangedPrefix = 0;
    const sharedLength = Math.min(this.#rendered.length, lines.length);
    while (unchangedPrefix < sharedLength && this.#rendered[unchangedPrefix] === lines[unchangedPrefix]) {
      unchangedPrefix += 1;
    }

    // Terminal cursor activity normally changes only the unfinished tail.
    if (unchangedPrefix >= sharedLength - MAX_INCREMENTAL_TAIL) {
      while (this.#host.children.length > unchangedPrefix) {
        this.#host.lastElementChild?.remove();
      }
      this.#rendered.length = unchangedPrefix;
      this.#append(lines, unchangedPrefix);
      return;
    }

    const fragment = this.#host.ownerDocument.createDocumentFragment();
    for (const line of lines) fragment.append(this.#createLine(line));
    this.#host.replaceChildren(fragment);
    this.#rendered = [...lines];
    this.#source = lines;
  }

  #append(lines: readonly TerminalLine[], from: number): void {
    if (from < lines.length) {
      const fragment = this.#host.ownerDocument.createDocumentFragment();
      for (let index = from; index < lines.length; index += 1) {
        const line = lines[index];
        if (line !== undefined) {
          fragment.append(this.#createLine(line));
          this.#rendered.push(line);
        }
      }
      this.#host.append(fragment);
    }
    this.#source = lines;
  }
}

const MAX_INCREMENTAL_TAIL = 8;
