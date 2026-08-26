import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AutomataMark } from "../../src/components/AutomataMark";
import { Icon } from "../../src/components/Icon";
import { StatusBadge } from "../../src/components/StatusBadge";
import { renderPage } from "../../src/entry-server";
import { runDetailRequest, runListRequest } from "../fixtures/renderRequests";

describe("icon contract", () => {
  it("reserves inline SVG for the official mark and uses Phosphor for interface icons", () => {
    const html = `${renderPage(runListRequest)}${renderPage(runDetailRequest)}`;

    expect(html.match(/<svg/gu)).toHaveLength(4);
    expect(html).toContain('viewBox="0 0 14 9"');
    expect(html).toContain("ph ph-play-circle");
    expect(html).toContain("ph ph-circle-notch");
  });

  it("keeps the official Automata mark decorative beside its text label", () => {
    const html = renderToStaticMarkup(<AutomataMark />);

    expect(html).toContain('aria-hidden="true"');
    expect(html).toContain('focusable="false"');
    expect(html.match(/<rect/gu)).toHaveLength(4);
  });

  it("includes the bundled Phosphor glyph used by repository settings", () => {
    const styles = readFileSync(
      resolve(process.cwd(), "src/styles/foundations/icons.css"),
      "utf8",
    );

    expect(styles).toContain(".ph.ph-gear-six::before");
    expect(styles).toContain('content: "\\e272"');
    expect(renderToStaticMarkup(<Icon name="settings" />)).toContain(
      "ph ph-gear-six",
    );
  });

  it("includes the bundled Phosphor glyph used by external links", () => {
    const styles = readFileSync(
      resolve(process.cwd(), "src/styles/foundations/icons.css"),
      "utf8",
    );

    expect(styles).toContain(".ph.ph-arrow-square-out::before");
    expect(styles).toContain('content: "\\e5de"');
    expect(renderToStaticMarkup(<Icon name="external-link" />)).toContain(
      "ph ph-arrow-square-out",
    );
  });

  it("includes the bundled Phosphor glyph used by organization links", () => {
    const styles = readFileSync(
      resolve(process.cwd(), "src/styles/foundations/icons.css"),
      "utf8",
    );

    expect(styles).toContain(".ph.ph-buildings::before");
    expect(styles).toContain('content: "\\e102"');
    expect(renderToStaticMarkup(<Icon name="organizations" />)).toContain(
      "ph ph-buildings",
    );
  });

  it("uses bundled Phosphor glyphs for the native account disclosure", () => {
    const styles = readFileSync(
      resolve(process.cwd(), "src/styles/foundations/icons.css"),
      "utf8",
    );

    expect(styles).toContain(".ph.ph-caret-down::before");
    expect(styles).toContain('content: "\\e136"');
    expect(styles).toContain(".ph.ph-sign-out::before");
    expect(styles).toContain('content: "\\e42a"');
    expect(renderToStaticMarkup(<Icon name="sign-out" />)).toContain(
      "ph ph-sign-out",
    );
  });

  it.each([
    ["neutral", "minus-circle"],
    ["queued", "clock"],
    ["running", "circle-notch"],
    ["success", "check-circle"],
    ["failure", "x-circle"],
    ["warning", "warning-circle"],
  ] as const)(
    "keeps an accessible name for the %s icon-only status",
    (tone, icon) => {
      const html = renderToStaticMarkup(
        <StatusBadge
          labelMode="accessible"
          status={{ label: `Status: ${tone}`, tone }}
        />,
      );

      expect(html).toContain(`ph-${icon}`);
      expect(html).toContain('aria-hidden="true"');
      expect(html).toContain('role="img"');
      expect(html).toContain(`aria-label="Status: ${tone}"`);
      expect(html).not.toContain('class="status__label"');
    },
  );

  it("renders visible and decorative status modes without duplicate accessible text", () => {
    const status = { label: "In progress", tone: "running" } as const;
    const visible = renderToStaticMarkup(<StatusBadge status={status} />);
    const decorative = renderToStaticMarkup(
      <StatusBadge labelMode="none" status={status} />,
    );

    expect(visible).toContain('<span class="status__label">In progress</span>');
    expect(visible).not.toContain('role="img"');
    expect(decorative).toContain('aria-hidden="true"');
    expect(decorative).not.toContain("In progress");
    expect(decorative).not.toContain('role="img"');
  });
});
