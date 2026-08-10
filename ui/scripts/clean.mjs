import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const outputDirectory = fileURLToPath(new URL("../dist", import.meta.url));
const arguments_ = process.argv.slice(2);

if (arguments_.length === 0) {
  await rm(outputDirectory, { recursive: true, force: true });
} else if (arguments_.length === 1 && arguments_[0] === "--production") {
  await Promise.all(
    ["client", "ssr"].map((directory) =>
      rm(`${outputDirectory}/${directory}`, { recursive: true, force: true }),
    ),
  );
} else {
  throw new Error("Usage: node scripts/clean.mjs [--production]");
}
