import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  Shell,
  ShellFooterLinksProvider,
} from "../../src/components/Shell";
import { previewShell } from "../../src/preview/sampleData";

describe("Shell footer", () => {
  it("renders the product identity without SaaS links by default", () => {
    const html = renderToStaticMarkup(
      <Shell repository={null} shell={previewShell}>
        <main id="main-content" />
      </Shell>,
    );

    expect(html).toContain('class="site-footer__mark"');
    expect(html).toContain('class="site-footer__brand-label">Automata</span>');
    expect(html).not.toContain('aria-label="Footer navigation"');
  });

  it("renders host-supplied footer navigation", () => {
    const html = renderToStaticMarkup(
      <Shell
        footerLinks={[
          { href: "#terms", label: "Terms" },
          { href: "#privacy", label: "Privacy" },
        ]}
        repository={null}
        shell={{ ...previewShell, productName: "Automata Cloud" }}
      >
        <main id="main-content" />
      </Shell>,
    );

    expect(html).toContain(
      'class="site-footer__brand-label">Automata Cloud</span>',
    );
    expect(html).toContain(
      '<nav class="site-footer__navigation" aria-label="Footer navigation">',
    );
    expect(html).toContain('<a href="#terms">Terms</a>');
    expect(html).toContain('<a href="#privacy">Privacy</a>');
  });

  it("inherits footer navigation from a composed host", () => {
    const html = renderToStaticMarkup(
      <ShellFooterLinksProvider
        links={[{ href: "#status", label: "Status" }]}
      >
        <Shell repository={null} shell={previewShell}>
          <main id="main-content" />
        </Shell>
      </ShellFooterLinksProvider>,
    );

    expect(html).toContain('aria-label="Footer navigation"');
    expect(html).toContain('<a href="#status">Status</a>');
  });
});
