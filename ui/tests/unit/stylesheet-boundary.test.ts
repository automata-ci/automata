import { readdirSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const sourceRoot = resolve(process.cwd(), "src");

describe("stylesheet entrypoint boundaries", () => {
  it("keeps every production module reachable exactly once through the layered entrypoint", () => {
    const applicationEntry = source("styles.css");
    const imports = [
      ...applicationEntry.matchAll(
        /@import\s+"\.\/(styles\/[^"\n]+\.css)"\s+layer\([^)]+\);/gu,
      ),
    ]
      .map((match) => match[1])
      .filter((path): path is string => path !== undefined);
    const productionModules = styleModules().filter(
      (path) => path !== "styles/pages/preview.css",
    );

    expect(applicationEntry).toMatch(
      /^@layer reset, tokens, base, layout, components, pages, conditions;/u,
    );
    expect(imports).toHaveLength(new Set(imports).size);
    expect([...imports].sort()).toEqual([...productionModules].sort());
    expect(
      applicationEntry
        .replace(/^@layer[^;]+;/u, "")
        .replace(/^\s*@import[^;]+;/gmu, "")
        .trim(),
    ).toBe("");
  });

  it("keeps the semantic token graph complete and raw palette values isolated", () => {
    const modules = styleModules();
    const styles = modules.map((path) => source(path));
    const declaredTokens = new Set(
      styles.flatMap((style) =>
        [...style.matchAll(/(?:^|[;{])\s*(--[a-z0-9-]+)\s*:/gmu)].map(
          (match) => match[1],
        ),
      ),
    );
    const consumedTokens = new Set(
      styles.flatMap((style) =>
        [...style.matchAll(/var\((--[a-z0-9-]+)/gu)].map(
          (match) => match[1],
        ),
      ),
    );

    expect([...consumedTokens].sort()).toEqual([...declaredTokens].sort());
    for (const path of modules) {
      if (path !== "styles/foundations/tokens.css") {
        expect(source(path), path).not.toMatch(
          /#[0-9a-f]{3,8}\b|(?:rgb|hsl)a?\(/iu,
        );
      }
    }
  });

  it("keeps preview-only rules out of the production stylesheet graph", () => {
    const applicationEntry = source("styles.css");
    const previewEntry = source("preview.tsx");
    const previewStyles = source("styles/pages/preview.css");
    const emptyState = source("components/EmptyState.tsx");

    expect(applicationEntry).not.toContain("pages/preview.css");
    expect(previewEntry).toContain('import "./styles/pages/preview.css";');
    expect(previewStyles.trimStart()).toMatch(/^@layer pages\s*\{/u);
    expect(emptyState).not.toContain("preview-not-found");
  });

  it("routes every supported preview page through the application boundary", () => {
    const previewEntry = source("preview.tsx");

    expect(previewEntry).not.toMatch(/from "\.\/pages\//u);
    expect(previewEntry.match(/<App page=/gu)).toHaveLength(1);
    expect(previewEntry).toContain("renderPreviewPage(runDetail)");
    expect(previewEntry).toContain("renderPreviewPage(jobLog)");
    expect(previewEntry).toContain("renderPreviewPage(previewRepositorySettings())");
    expect(previewEntry).toContain("renderPreviewPage(previewRepositoryDirectory(");
    expect(previewEntry).toContain("renderPreviewPage(previewRunList(searchParameters))");
  });

  it("keeps reusable compact empty-state styling in the component layer", () => {
    const componentStyles = source("styles/components/surfaces.css");
    const runDetailStyles = source("styles/pages/run-detail.css");

    expect(componentStyles).toContain(".compact-empty-state > p");
    expect(runDetailStyles).not.toContain(".compact-empty-state");
  });

  it("keeps the account menu anchored, focusable, and coarse-pointer friendly", () => {
    const layoutStyles = source("styles/layout/shell.css");
    const componentStyles = source("styles/components/shell.css");
    const accessibilityStyles = source("styles/foundations/accessibility.css");
    const responsiveStyles = source("styles/conditions/responsive.css");

    expect(layoutStyles).toMatch(
      /\.viewer-menu__popover\s*\{[^}]*position:\s*absolute;/su,
    );
    expect(componentStyles).toMatch(
      /\.viewer-menu\s*>\s*summary\s*\{[^}]*cursor:\s*pointer;/su,
    );
    expect(accessibilityStyles).toContain(":focus-visible");
    expect(responsiveStyles).toMatch(
      /@media \(any-pointer: coarse\)[\s\S]*\.viewer-menu__sign-out,[\s\S]*min-height:\s*40px;/u,
    );
  });
});

function source(relativePath: string): string {
  return readFileSync(resolve(sourceRoot, relativePath), "utf8");
}

function styleModules(): string[] {
  const stylesRoot = resolve(sourceRoot, "styles");

  return walk(stylesRoot)
    .filter((path) => path.endsWith(".css"))
    .map((path) => relative(sourceRoot, path));
}

function walk(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}
