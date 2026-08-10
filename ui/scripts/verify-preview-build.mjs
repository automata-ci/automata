import { access, readFile, readdir } from "node:fs/promises";

const uiRoot = new URL("../", import.meta.url);
const outputDirectory = new URL("dist/preview/", uiRoot);
const indexUrl = new URL("index.html", outputDirectory);
const assetsDirectory = new URL("assets/", outputDirectory);
const screenshotsDirectory = new URL("screenshots/", outputDirectory);
const cliArguments = process.argv.slice(2);
const verifyScreenshots =
  cliArguments.length === 1 && cliArguments[0] === "--with-screenshots";
if (cliArguments.length !== 0 && !verifyScreenshots) {
  throw new Error(
    `Unknown preview verification arguments: ${cliArguments.join(" ")}`,
  );
}

const rootEntries = await readdir(outputDirectory, { withFileTypes: true });
const rootShape = rootEntries
  .map((entry) => {
    const kind = entry.isDirectory()
      ? "directory"
      : entry.isFile()
        ? "file"
        : "other";
    return `${kind}:${entry.name}`;
  })
  .sort();
if (
  JSON.stringify(rootShape) !==
  JSON.stringify(
    verifyScreenshots
      ? ["directory:assets", "directory:screenshots", "file:index.html"]
      : ["directory:assets", "file:index.html"],
  )
) {
  throw new Error(
    `Fresh preview output must contain only index.html and assets/: ${rootShape.join(", ")}`,
  );
}

const html = await readFile(indexUrl, "utf8");
if (/<base\b/iu.test(html)) {
  throw new Error(
    "Preview index must not override relative URL resolution with <base>",
  );
}
if (!html.includes("sample-data demo") || !html.includes("<noscript>")) {
  throw new Error(
    "Preview index must identify the sample-data demo and its JS requirement",
  );
}

const scriptSources = attributeValues(html, "script", "src");
const stylesheetHrefs = stylesheetUrls(html);
if (scriptSources.length !== 1 || stylesheetHrefs.length !== 1) {
  throw new Error(
    [
      "Preview index must emit one script and one stylesheet;",
      `got ${scriptSources.length} scripts and ${stylesheetHrefs.length} stylesheets`,
    ].join(" "),
  );
}

const emittedAssets = new Set(
  (await readdir(assetsDirectory, { withFileTypes: true })).map((entry) => {
    if (!entry.isFile()) {
      throw new Error(`Preview asset must be a regular file: ${entry.name}`);
    }
    return `./assets/${entry.name}`;
  }),
);
const referencedAssets = new Set([...scriptSources, ...stylesheetHrefs]);
for (const asset of referencedAssets) {
  requireDirectRelativeAsset(asset);
  await access(new URL(asset, indexUrl));
}

for (const stylesheet of stylesheetHrefs) {
  const source = await readFile(new URL(stylesheet, indexUrl), "utf8");
  for (const asset of cssUrls(source)) {
    if (asset.startsWith("data:") || asset.startsWith("#")) {
      continue;
    }
    if (!/^\.\/[^/]+$/u.test(asset)) {
      throw new Error(`Preview CSS asset must be relative to assets/: ${asset}`);
    }
    const relativeToIndex = `./assets/${asset.slice(2)}`;
    referencedAssets.add(relativeToIndex);
    await access(new URL(asset, new URL(stylesheet, indexUrl)));
  }
}

const actual = [...emittedAssets].sort();
const expected = [...referencedAssets].sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  throw new Error(
    [
      "Preview output contains an unreferenced or missing asset;",
      `expected ${expected.join(", ")}, got ${actual.join(", ")}`,
    ].join(" "),
  );
}

if (verifyScreenshots) {
  await verifyScreenshotOutput();
}

process.stdout.write(
  `Verified relative Pages preview (${scriptSources[0]}, ${stylesheetHrefs[0]}).\n`,
);

function attributeValues(source, tagName, attributeName) {
  const tags = source.match(new RegExp(`<${tagName}\\b[^>]*>`, "giu")) ?? [];
  const attribute = new RegExp(`\\b${attributeName}="([^"]+)"`, "iu");
  return tags.flatMap((tag) => {
    const match = tag.match(attribute);
    return match?.[1] === undefined ? [] : [match[1]];
  });
}

function stylesheetUrls(source) {
  return (source.match(/<link\b[^>]*>/giu) ?? []).flatMap((tag) => {
    if (!/\brel="stylesheet"/iu.test(tag)) {
      return [];
    }
    const match = tag.match(/\bhref="([^"]+)"/iu);
    return match?.[1] === undefined ? [] : [match[1]];
  });
}

function cssUrls(source) {
  return [
    ...source.matchAll(/url\(\s*["']?([^"')\s]+)["']?\s*\)/giu),
  ].flatMap((match) => (match[1] === undefined ? [] : [match[1]]));
}

function requireDirectRelativeAsset(asset) {
  if (!/^\.\/assets\/[^/]+\.(?:css|js)$/u.test(asset)) {
    throw new Error(
      `Preview executable/style asset must be a direct relative URL: ${asset}`,
    );
  }
}

async function verifyScreenshotOutput() {
  const expectedScreenshots = [
    "repositories",
    "repositories-empty",
    "workflow-runs",
    "run-summary",
    "job-logs",
    "repository-access-settings",
    "repository-secrets",
    "access-users",
    "access-user-detail",
    "access-roles",
    "access-role-detail",
    "access-direct-bindings",
  ]
    .flatMap((page) =>
      ["", "-tablet", "-mobile"].flatMap((viewport) =>
        ["light", "dark"].map(
          (theme) => `${page}${viewport}-${theme}.png`,
        ),
      ),
    )
    .sort();
  const entries = await readdir(screenshotsDirectory, { withFileTypes: true });
  const actualScreenshots = entries.map((entry) => {
    if (!entry.isFile()) {
      throw new Error(`Preview screenshot must be a regular file: ${entry.name}`);
    }
    return entry.name;
  });
  actualScreenshots.sort();
  if (JSON.stringify(actualScreenshots) !== JSON.stringify(expectedScreenshots)) {
    throw new Error(
      [
        "Preview screenshot set is incomplete or contains an unexpected file;",
        `expected ${expectedScreenshots.join(", ")},`,
        `got ${actualScreenshots.join(", ")}`,
      ].join(" "),
    );
  }

  const pngSignature = "89504e470d0a1a0a";
  for (const screenshot of actualScreenshots) {
    const contents = await readFile(new URL(screenshot, screenshotsDirectory));
    if (contents.length <= 8 || contents.subarray(0, 8).toString("hex") !== pngSignature) {
      throw new Error(`Preview screenshot is not a non-empty PNG: ${screenshot}`);
    }
  }
}
