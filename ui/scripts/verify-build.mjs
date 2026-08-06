import { access, readFile, readdir } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const ssrDirectory = new URL("dist/ssr/", root);
const rendererUrl = new URL("renderer.mjs", ssrDirectory);
const manifestUrl = new URL("dist/client/manifest.json", root);

const ssrFiles = (await readdir(ssrDirectory)).sort();
if (ssrFiles.length !== 1 || ssrFiles[0] !== "renderer.mjs") {
  throw new Error(`SSR output must be one renderer.mjs file; got: ${ssrFiles.join(", ")}`);
}

const rendererSource = await readFile(rendererUrl, "utf8");
if (/\b(?:from\s*|import\s*\()["'](?:node:|react(?:-dom)?(?:\/|["']))/.test(rendererSource)) {
  throw new Error("SSR renderer contains a Node builtin or external React import");
}

const renderer = await import(`${rendererUrl.href}?verify=${Date.now()}`);
if (typeof renderer.render !== "function") {
  throw new Error("SSR renderer does not export render(serializedRequest)");
}

const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
const entry = manifest["src/entry-client.tsx"];
if (entry?.isEntry !== true || typeof entry.file !== "string" || !Array.isArray(entry.css)) {
  throw new Error("Client manifest is missing the hydrated entry or its CSS assets");
}

await access(new URL(`dist/client/${entry.file}`, root));
for (const stylesheet of entry.css) {
  await access(new URL(`dist/client/${stylesheet}`, root));
}

const smokeRequest = {
  schemaVersion: 1,
  host: {
    locale: "en",
    assets: { clientEntry: `/${entry.file}`, stylesheets: entry.css.map((file) => `/${file}`) },
  },
  page: {
    kind: "run-list",
    shell: {
      productName: "Automata",
      homeHref: "/",
      signInHref: "/login",
      documentTitle: "Runs · Automata",
      description: "Workflow runs",
      viewer: null,
      navigation: [{ label: "Runs", href: "/runs", current: true }],
    },
    repository: {
      owner: "automata",
      name: "automata",
      href: "/automata/automata",
      runsHref: "/automata/automata/actions/runs",
    },
    heading: "Workflow runs",
    summary: "Self-hosted CI activity",
    filters: {
      action: "/automata/automata/actions/runs",
      status: "all",
      branch: "",
      statusOptions: [{ value: "all", label: "All statuses" }],
      clearHref: "/automata/automata/actions/runs",
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
