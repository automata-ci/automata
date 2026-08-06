import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectBoolean,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  hasOwn,
  invalid,
} from "./primitives";

export function validateShell(value: unknown, path: string): void {
  const shell = expectObject(value, path, [
    "productName",
    "homeHref",
    "signInHref",
    "documentTitle",
    "description",
    "viewer",
    "navigation",
  ]);
  expectTextField(shell, "productName", path);
  expectRouteField(shell, "homeHref", path);
  expectRouteField(shell, "signInHref", path);
  expectTextField(shell, "documentTitle", path);
  expectTextField(shell, "description", path, RENDER_REQUEST_LIMITS.longTextLength);

  if (shell.viewer !== null) {
    const viewerPath = `${path}.viewer`;
    const viewer = expectObject(shell.viewer, viewerPath, ["displayName", "profileHref"]);
    expectTextField(viewer, "displayName", viewerPath);
    expectRouteField(viewer, "profileHref", viewerPath);
  }

  const navigationPath = `${path}.navigation`;
  const navigation = expectArray(
    shell.navigation,
    navigationPath,
    RENDER_REQUEST_LIMITS.navigationCount,
  );
  const seenHrefs = new Set<string>();
  navigation.forEach((item, index) => {
    const itemPath = `${navigationPath}[${index}]`;
    const navigationItem = expectObject(item, itemPath, ["label", "href"], ["current"]);
    expectTextField(navigationItem, "label", itemPath);
    const href = expectRouteField(navigationItem, "href", itemPath);
    expectUnique(seenHrefs, href, `${itemPath}.href`);
    if (hasOwn(navigationItem, "current")) {
      expectBoolean(navigationItem.current, `${itemPath}.current`);
    }
  });
}

export function validateRepository(value: unknown, path: string): void {
  const repository = expectObject(value, path, ["owner", "name", "href", "runsHref"]);
  expectTextField(repository, "owner", path);
  expectTextField(repository, "name", path);
  expectRouteField(repository, "href", path);
  expectRouteField(repository, "runsHref", path);
}

export function validateCommit(value: unknown, path: string): void {
  const commit = expectObject(value, path, ["shortSha", "message", "href"]);
  const shortSha = expectString(commit.shortSha, `${path}.shortSha`, 64, 4);
  if (!/^[a-fA-F0-9]+$/u.test(shortSha)) {
    invalid(`${path}.shortSha`, "a hexadecimal commit identifier");
  }
  expectString(commit.message, `${path}.message`, RENDER_REQUEST_LIMITS.longTextLength);
  expectRouteField(commit, "href", path);
}

export function validateStatus(value: unknown, path: string): void {
  const status = expectObject(value, path, ["label", "tone"]);
  expectTextField(status, "label", path);
  expectOneOf(status.tone, `${path}.tone`, [
    "neutral",
    "queued",
    "running",
    "success",
    "failure",
    "warning",
  ]);
}

export function validateTimestamp(value: unknown, path: string): void {
  const timestamp = expectObject(value, path, ["iso", "label"]);
  const iso = expectString(timestamp.iso, `${path}.iso`, 64, 20);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u.test(iso) ||
    Number.isNaN(Date.parse(iso))
  ) {
    invalid(`${path}.iso`, "an RFC 3339 timestamp");
  }
  expectTextField(timestamp, "label", path);
}
