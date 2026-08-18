import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const sourceRoot = path.join(root, "src");
const failures = [];

const presentationReplacements = new Map([
  ["components/ThemeToggle.tsx", "components/ThemeToggleView.stories.tsx"],
  ["pages/JobLogPage.tsx", "views/JobLogPageView.stories.tsx"],
  ["pages/RepositorySettingsPage.tsx", "views/RepositorySettingsPageView.stories.tsx"],
  ["pages/SetupPage.tsx", "views/SetupPageView.stories.tsx"],
]);

for (const relative of componentFiles("components")) requireStory(relative);
for (const relative of componentFiles("pages")) requireStory(relative);
for (const relative of componentFiles("views")) {
  requireStory(relative);
  verifyPureView(relative);
}

for (const relative of sourceFiles("services", ".ts")) {
  const source = readFile(relative);
  if (/from\s+["']react(?:\/[\w-]+)?["']/u.test(source)) {
    failures.push(`${display(relative)}: services must not import React`);
  }
}

if (failures.length > 0) {
  throw new Error(`Presentation architecture check failed:\n- ${failures.join("\n- ")}`);
}

console.log("Presentation boundaries and Storybook coverage are complete.");

function componentFiles(directory) {
  return sourceFiles(directory, ".tsx")
    .map((file) => display(file))
    .filter((file) => !file.endsWith(".stories.tsx"));
}

function sourceFiles(directory, extension) {
  const absolute = path.join(sourceRoot, directory);
  return readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(absolute, entry.name);
    if (entry.isDirectory()) return [];
    return entry.isFile() && entry.name.endsWith(extension) ? [target] : [];
  });
}

function requireStory(relative) {
  const replacement = presentationReplacements.get(relative);
  const story = replacement ?? relative.replace(/\.tsx$/u, ".stories.tsx");
  if (!existsSync(path.join(sourceRoot, story))) {
    failures.push(`${relative}: missing co-located presentation story`);
  }
}

function verifyPureView(relative) {
  const absolute = path.join(sourceRoot, relative);
  const source = readFile(absolute);
  const businessImport = source.match(
    /from\s+["']([^"']*\/(?:hooks|services|pages|validation)(?:\/[^"']*)?|[^"']*\/logs\/(?:controller|protocol))["']/u,
  );
  if (businessImport !== null) {
    failures.push(`${relative}: presentation must not import business module ${JSON.stringify(businessImport[1])}`);
  }
  const hookCall = source.match(/\b(use[A-Z][A-Za-z0-9_]*)\s*\(/u);
  if (hookCall !== null) {
    failures.push(`${relative}: presentation calls React hook ${hookCall[1]}`);
  }
  const browserReference = source.match(
    /\b(fetch|window|document|crypto|localStorage|sessionStorage)\b/u,
  );
  if (browserReference !== null) {
    failures.push(`${relative}: presentation references browser global ${browserReference[1]}`);
  }
}

function readFile(file) {
  return readFileSync(file, "utf8");
}

function display(file) {
  return path.relative(sourceRoot, file).split(path.sep).join("/");
}
