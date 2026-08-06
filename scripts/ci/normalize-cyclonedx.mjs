#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  normalizeCycloneDx,
  serializeCanonicalJson,
} from "./lib/cyclonedx.mjs";

const [, , inputPath, outputPath, repositoryRoot, epochText, componentSha256] =
  process.argv;

if (
  inputPath === undefined ||
  outputPath === undefined ||
  repositoryRoot === undefined ||
  epochText === undefined ||
  process.argv.length > 7
) {
  console.error(
    "usage: normalize-cyclonedx.mjs INPUT OUTPUT REPOSITORY_ROOT SOURCE_DATE_EPOCH [COMPONENT_SHA256]",
  );
  process.exitCode = 2;
} else {
  const input = JSON.parse(await readFile(inputPath, "utf8"));
  const normalized = normalizeCycloneDx(input, {
    repositoryRoot,
    sourceDateEpoch: Number(epochText),
    componentSha256,
  });
  await writeFile(path.resolve(outputPath), serializeCanonicalJson(normalized), {
    encoding: "utf8",
    mode: 0o644,
  });
}
