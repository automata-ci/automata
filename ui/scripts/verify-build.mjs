import { access, readFile, readdir } from "node:fs/promises";
import { assertClosedJavaScriptModule } from "./javascript-module-boundary.mjs";

const root = new URL("../", import.meta.url);
const ssrDirectory = new URL("dist/ssr/", root);
const rendererUrl = new URL("renderer.mjs", ssrDirectory);
const manifestUrl = new URL("dist/client/manifest.json", root);
const clientAssetsDirectory = new URL("dist/client/assets/", root);

const ssrFiles = (await readdir(ssrDirectory)).sort();
if (ssrFiles.length !== 1 || ssrFiles[0] !== "renderer.mjs") {
  throw new Error(`SSR output must be one renderer.mjs file; got: ${ssrFiles.join(", ")}`);
}

const rendererSource = await readFile(rendererUrl, "utf8");
assertClosedJavaScriptModule(rendererSource, "SSR renderer");

const renderer = await import(`${rendererUrl.href}?verify=${Date.now()}`);
if (typeof renderer.render !== "function") {
  throw new Error("SSR renderer does not export render(serializedRequest)");
}

const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
const entry = manifest["src/entry-client.tsx"];
if (
  entry?.isEntry !== true ||
  typeof entry.file !== "string" ||
  !/\.m?js$/u.test(entry.file) ||
  !Array.isArray(entry.css) ||
  entry.css.length !== 1 ||
  entry.css.some(
    (stylesheet) => typeof stylesheet !== "string" || !/\.css$/u.test(stylesheet),
  )
) {
  throw new Error("Client manifest is missing the hydrated entry or its CSS assets");
}

const embeddedClientAssets = [entry.file, ...entry.css].sort();
if (embeddedClientAssets.some((asset) => !/^assets\/[^/]+$/u.test(asset))) {
  throw new Error(`Client assets must be direct children of assets/: ${embeddedClientAssets.join(", ")}`);
}
const emittedClientAssets = (await readdir(clientAssetsDirectory))
  .map((asset) => `assets/${asset}`)
  .sort();
if (JSON.stringify(emittedClientAssets) !== JSON.stringify(embeddedClientAssets)) {
  throw new Error(
    `Client output contains an asset the Rust embedder would not serve; expected ${embeddedClientAssets.join(", ")}, got ${emittedClientAssets.join(", ")}`,
  );
}
for (const asset of embeddedClientAssets) {
  await access(new URL(`dist/client/${asset}`, root));
}

const clientSource = await readFile(
  new URL(`dist/client/${entry.file}`, root),
  "utf8",
);
assertClosedJavaScriptModule(clientSource, "Client hydration entry");

const stylesheetSource = await readFile(new URL(`dist/client/${entry.css[0]}`, root), "utf8");
if (!stylesheetSource.includes("data:font/woff2;base64,")) {
  throw new Error("Client CSS must inline the WOFF2 icon font for the Rust asset boundary");
}
if (/data:image\/svg\+xml/iu.test(stylesheetSource)) {
  throw new Error("Client CSS must not contain inline SVG assets");
}

const smokeRequest = {
  schemaVersion: 1,
  host: {
    locale: "en",
    cspNonce: "build-verifier-nonce",
    assets: { clientEntry: `/${entry.file}`, stylesheets: entry.css.map((file) => `/${file}`) },
  },
  page: {
    kind: "run-list",
    shell: {
      accountNavigation: [],
      productName: "Automata",
      homeHref: "/repositories",
      signIn: { action: "/auth/github/login", returnPath: "/automata-ci/automata/actions" },
      signOut: null,
      documentTitle: "Workflow runs · Automata",
      description: "Workflow runs",
      viewer: null,
      navigation: [
        { label: "Repositories", href: "/repositories", current: false },
        { label: "Runners", href: "/runners", current: false },
        { label: "Actions", href: "/automata-ci/automata/actions", current: true },
      ],
    },
    repository: {
      owner: "automata-ci",
      name: "automata",
      sourceHref: "https://github.com/automata-ci/automata",
      runsHref: "/automata-ci/automata/actions",
      settingsHref: null,
    },
    heading: "Workflow runs",
    summary: "Self-hosted CI activity",
    workflowNavigation: null,
    filters: {
      action: "/automata-ci/automata/actions",
      status: "all",
      branch: "",
      clearHref: "/automata-ci/automata/actions",
    },
    runs: [],
    pagination: { previousHref: null, nextHref: null, label: "0 runs" },
  },
};

const html = renderer.render(JSON.stringify(smokeRequest));
if (!html.startsWith("<!doctype html>") || !html.includes("Workflow runs")) {
  throw new Error("Bundled renderer did not return a complete server-rendered document");
}

const unsafeAssetRequest = structuredClone(smokeRequest);
unsafeAssetRequest.host.assets.clientEntry = "https://evil.invalid/client.js";
assertRejected(unsafeAssetRequest, "$.host.assets.clientEntry");

const unsafeRouteRequest = structuredClone(smokeRequest);
unsafeRouteRequest.page.filters.action = "javascript:alert(1)";
assertRejected(unsafeRouteRequest, "$.page.filters.action");

const unsafeSourceRequest = structuredClone(smokeRequest);
unsafeSourceRequest.page.repository.sourceHref = "https://github.com.evil.invalid/automata-ci/automata";
assertRejected(unsafeSourceRequest, "$.page.repository.sourceHref");

const byteCount = Buffer.byteLength(rendererSource);
await new Promise((resolve) => {
  process.stdout.write(
    `Verified bundled SSR renderer (${byteCount} bytes), client entry, manifest, CSS, and smoke render.\n`,
    resolve,
  );
});

// React's worker-compatible scheduler owns a MessageChannel after import. This
// verifier is a finished build-time CLI, so close it explicitly rather than
// leaving npm waiting on that scheduler port.
process.exit(0);

function assertRejected(request, expectedPath) {
  try {
    renderer.render(JSON.stringify(request));
  } catch (error) {
    if (error instanceof Error && error.message.includes(expectedPath)) {
      return;
    }
    throw error;
  }
  throw new Error(`Bundled renderer accepted unsafe input at ${expectedPath}`);
}
