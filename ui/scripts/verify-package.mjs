import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const execute = promisify(execFile);
const root = new URL("../", import.meta.url);
const packageApi = await import(
  `${new URL("dist/package/index.js", root).href}?verify=${Date.now()}`
);
const expectedExports = [
  "App",
  "LIVE_LOG_PROTOCOL_VERSION",
  "LiveLogController",
  "LiveLogProtocolError",
  "LiveLogRequestError",
  "ProviderConnectionPanel",
  "RepositorySelectionList",
  "Shell",
  "THEME_BOOTSTRAP_SCRIPT",
  "ThemeToggle",
  "createSameOriginLiveLogAccessProvider",
  "installViewerMenuDismissal",
  "validateLiveLogAccess",
];

if (JSON.stringify(Object.keys(packageApi).sort()) !== JSON.stringify(expectedExports)) {
  throw new Error(
    `Unexpected public UI runtime exports: ${Object.keys(packageApi).sort().join(", ")}`,
  );
}

const shellHtml = renderToStaticMarkup(
  createElement(
    packageApi.Shell,
    {
      repository: null,
      shell: {
        accountNavigation: [],
        productName: "Automata",
        homeHref: "/",
        signIn: null,
        signOut: null,
        documentTitle: "Automata Cloud",
        description: "Automata Cloud",
        viewer: { displayName: "Package consumer" },
        navigation: [{ label: "Workspaces", href: "/", current: true }],
      },
      utility: null,
    },
    createElement("main", { id: "main-content" }, "Consumer content"),
  ),
);
if (
  !shellHtml.includes("Package consumer") ||
  !shellHtml.includes("Consumer content")
) {
  throw new Error("Public Shell did not render consumer-owned content");
}

const stylesheet = await readFile(
  new URL("dist/package/styles.css", root),
  "utf8",
);
if (
  !stylesheet.includes(".site-header") ||
  !stylesheet.includes("data:font/woff2;base64,")
) {
  throw new Error("Packaged stylesheet is missing the shared shell or icon font");
}

const packageDirectory = new URL(".", root);
const firstDirectory = await mkdtemp(join(tmpdir(), "automata-ui-pack-a-"));
const secondDirectory = await mkdtemp(join(tmpdir(), "automata-ui-pack-b-"));
try {
  const first = await pack(packageDirectory, firstDirectory);
  const second = await pack(packageDirectory, secondDirectory);
  const firstArchive = await readFile(join(firstDirectory, first.filename));
  const secondArchive = await readFile(join(secondDirectory, second.filename));
  const firstDigest = digest(firstArchive);
  const secondDigest = digest(secondArchive);

  if (firstDigest !== secondDigest) {
    throw new Error(
      `Repeated npm pack output was not deterministic: ${firstDigest} != ${secondDigest}`,
    );
  }

  const files = first.files.map(({ path }) => path);
  for (const required of [
    "dist/package/index.js",
    "dist/package/public.d.ts",
    "dist/package/styles.css",
    "package.json",
    "README.md",
  ]) {
    if (!files.includes(required)) {
      throw new Error(`npm package is missing ${required}`);
    }
  }
  const unexpected = files.filter(
    (file) =>
      file !== "package.json" &&
      file !== "README.md" &&
      !file.startsWith("dist/package/"),
  );
  if (unexpected.length > 0) {
    throw new Error(`npm package contains unexpected files: ${unexpected.join(", ")}`);
  }

  await verifyTypeScriptConsumer(join(firstDirectory, first.filename));

  process.stdout.write(
    `Verified composable UI package (${files.length} files, sha256:${firstDigest}).\n`,
  );
} finally {
  await Promise.all([
    rm(firstDirectory, { recursive: true, force: true }),
    rm(secondDirectory, { recursive: true, force: true }),
  ]);
}

async function pack(directory, destination) {
  const { stdout } = await execute(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
    { cwd: directory },
  );
  const result = JSON.parse(stdout);
  if (!Array.isArray(result) || result.length !== 1) {
    throw new Error("npm pack did not report exactly one archive");
  }
  return result[0];
}

async function verifyTypeScriptConsumer(archive) {
  const consumerDirectory = await mkdtemp(
    join(tmpdir(), "automata-ui-consumer-"),
  );
  try {
    const nodeModules = join(consumerDirectory, "node_modules");
    const installedPackage = join(nodeModules, "@automata", "ui");
    await mkdir(installedPackage, { recursive: true });
    await execute(
      "tar",
      ["-xzf", archive, "--strip-components=1", "-C", installedPackage],
    );

    for (const dependency of ["react", "react-dom", "@types"]) {
      const destination = join(nodeModules, dependency);
      await mkdir(dirname(destination), { recursive: true });
      await symlink(
        fileURLToPath(new URL(`node_modules/${dependency}`, root)),
        destination,
      );
    }

    await writeFile(
      join(consumerDirectory, "consumer.mts"),
      `import {
  App,
  installViewerMenuDismissal,
  validateLiveLogAccess,
  type AppProps,
  type JobLogPageModel,
  type LiveLogAccess,
  type LiveLogAccessProvider,
  type LiveLogRecord,
} from "@automata/ui";

declare const access: LiveLogAccess;
declare const accessProvider: LiveLogAccessProvider;
declare const page: JobLogPageModel;
declare const record: LiveLogRecord;

const props: AppProps = { page, jobLogAccess: accessProvider };
void App;
void installViewerMenuDismissal;
void props;
void record;
validateLiveLogAccess(access);
`,
    );
    await writeFile(
      join(consumerDirectory, "tsconfig.json"),
      `${JSON.stringify(
        {
          compilerOptions: {
            exactOptionalPropertyTypes: true,
            module: "NodeNext",
            moduleResolution: "NodeNext",
            noEmit: true,
            skipLibCheck: true,
            strict: true,
            target: "ES2022",
          },
          include: ["consumer.mts"],
        },
        null,
        2,
      )}\n`,
    );
    await execute(
      process.execPath,
      [
        fileURLToPath(new URL("node_modules/typescript/bin/tsc", root)),
        "--project",
        join(consumerDirectory, "tsconfig.json"),
      ],
      { cwd: consumerDirectory },
    );
  } finally {
    await rm(consumerDirectory, { recursive: true, force: true });
  }
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}
