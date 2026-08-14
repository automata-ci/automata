import { copyFile, readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(
  await readFile(new URL("dist/client/manifest.json", root), "utf8"),
);
const entry = manifest["src/entry-client.tsx"];

if (
  !Array.isArray(entry?.css) ||
  entry.css.length !== 1 ||
  typeof entry.css[0] !== "string"
) {
  throw new Error(
    "Client manifest must contain exactly one compiled UI stylesheet",
  );
}

await copyFile(
  new URL(`dist/client/${entry.css[0]}`, root),
  new URL("dist/package/styles.css", root),
);
