import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ProviderConnectionPanel,
  RepositorySelectionList,
} from "../../src/public";

describe("provider connection package components", () => {
  it("renders host-owned controls and escaped repository metadata", () => {
    const html = renderToStaticMarkup(
      <ProviderConnectionPanel
        accountLabel="analytical-engines"
        controls={<button type="button">Host action</button>}
        headingId="provider-example"
        lifecycle="active"
        providerLabel="GitHub"
      >
        <RepositorySelectionList
          repositories={[
            {
              defaultBranch: "main",
              id: "123",
              name: "<script>alert(1)</script>",
              owner: "automata-ci",
              private: true,
              selected: true,
            },
          ]}
        />
      </ProviderConnectionPanel>,
    );

    expect(html).toContain('data-provider-connection-state="active"');
    expect(html).toContain("Connected");
    expect(html).toContain("Host action");
    expect(html).toContain('name="repository_ids"');
    expect(html).toContain('value="123"');
    expect(html).toContain("Private · default branch main");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("renders read-only lifecycle and empty repository states", () => {
    const html = renderToStaticMarkup(
      <ProviderConnectionPanel
        accountLabel={null}
        headingId="provider-pending"
        lifecycle="suspended"
        providerLabel="Source provider"
      >
        <RepositorySelectionList disabled repositories={[]} />
      </ProviderConnectionPanel>,
    );

    expect(html).toContain("Installation pending");
    expect(html).toContain("Suspended");
    expect(html).toContain("No repositories are available");
  });
});
