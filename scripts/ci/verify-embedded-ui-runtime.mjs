import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyEmbeddedUiRuntime } from "./lib/embedded-ui-runtime.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = realpathSync(path.join(scriptDirectory, "../.."));
const policy = JSON.parse(
  readFileSync(
    path.join(scriptDirectory, "third-party-license-policy.json"),
    "utf8",
  ),
);
const verified = verifyEmbeddedUiRuntime({ policy, repositoryRoot });

console.log(
  `Verified ${verified.packages.length} locked embedded UI runtime packages`,
);
