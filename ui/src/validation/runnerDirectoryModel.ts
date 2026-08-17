import { validateShell, validateTimestamp } from "./commonModels";
import { RENDER_REQUEST_LIMITS, utf8ByteLength } from "./limits";
import {
  expectArray,
  expectInteger,
  expectLiteral,
  expectObject,
  expectOneOf,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

export function validateRunnerDirectoryPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind", "shell", "heading", "summary", "visibility", "counts", "runners",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "runner-directory");
  const shell = validateShell(page.shell, `${path}.shell`);
  const [repositoriesNavigation, runnersNavigation, accessNavigation] = shell.navigation;
  if (
    shell.homeHref !== "/repositories" ||
    (shell.navigation.length !== 2 && shell.navigation.length !== 3) ||
    repositoriesNavigation?.label !== "Repositories" ||
    repositoriesNavigation.href !== "/repositories" ||
    repositoriesNavigation.current ||
    runnersNavigation?.label !== "Runners" ||
    runnersNavigation.href !== "/runners" ||
    !runnersNavigation.current ||
    (accessNavigation !== undefined &&
      (accessNavigation.label !== "Access" ||
        accessNavigation.href !== "/settings/access/users" ||
        accessNavigation.current))
  ) {
    invalid(`${path}.shell.navigation`, "current Runners and coherent primary navigation");
  }
  expectTextField(page, "heading", path);
  expectTextField(page, "summary", path, RENDER_REQUEST_LIMITS.longTextLength);
  expectOneOf(page.visibility, `${path}.visibility`, ["private", "public"]);

  const runners = expectArray(page.runners, `${path}.runners`, RENDER_REQUEST_LIMITS.runnerCount);
  let online = 0;
  let busySlots = 0;
  let totalSlots = 0;
  const identities = new Set<string>();
  runners.forEach((value, index) => {
    const itemPath = `${path}.runners[${index}]`;
    const runner = expectObject(value, itemPath, [
      "name", "group", "labels", "status", "desiredState", "desiredStateLabel",
      "busySlots", "totalSlots", "lastSeenAt",
    ]);
    const name = expectTextField(runner, "name", itemPath);
    const group = runner.group === null ? null : expectTextField(runner, "group", itemPath);
    expectUnique(identities, `${group ?? ""}\0${name}`, `${itemPath}.name`);
    const labels = expectArray(runner.labels, `${itemPath}.labels`, 64);
    const seenLabels = new Set<string>();
    let labelBytes = 0;
    labels.forEach((label, labelIndex) => {
      const text = expectTextField({ label }, "label", `${itemPath}.labels[${labelIndex}]`);
      expectUnique(seenLabels, text, `${itemPath}.labels[${labelIndex}]`);
      labelBytes += utf8ByteLength(text);
    });
    if (labelBytes > 4_096) {
      invalid(`${itemPath}.labels`, "no more than 4096 UTF-8 bytes in total");
    }
    const status = expectObject(runner.status, `${itemPath}.status`, ["label", "tone"]);
    const statusLabel = expectOneOf(status.label, `${itemPath}.status.label`, ["Online", "Offline"]);
    const expectedTone = statusLabel === "Online" ? "success" : "neutral";
    if (status.tone !== expectedTone) invalid(`${itemPath}.status.tone`, expectedTone);
    if (statusLabel === "Online") online += 1;
    const desired = expectOneOf(runner.desiredState, `${itemPath}.desiredState`, ["active", "draining", "disabled"]);
    const expectedDesiredLabel = desired === "active" ? "Accepting jobs" : desired === "draining" ? "Draining" : "Disabled";
    if (runner.desiredStateLabel !== expectedDesiredLabel) invalid(`${itemPath}.desiredStateLabel`, expectedDesiredLabel);
    const itemBusy = expectInteger(runner.busySlots, `${itemPath}.busySlots`, 0, 65_535);
    const itemTotal = expectInteger(runner.totalSlots, `${itemPath}.totalSlots`, 1, 65_535);
    if (itemBusy > itemTotal) invalid(`${itemPath}.busySlots`, "no greater than totalSlots");
    busySlots += itemBusy;
    totalSlots += itemTotal;
    if (runner.lastSeenAt !== null) validateTimestamp(runner.lastSeenAt, `${itemPath}.lastSeenAt`);
  });

  const counts = expectObject(page.counts, `${path}.counts`, ["total", "online", "busySlots", "totalSlots"]);
  if (
    counts.total !== runners.length || counts.online !== online ||
    counts.busySlots !== busySlots || counts.totalSlots !== totalSlots
  ) {
    invalid(`${path}.counts`, "totals derived exactly from runner rows");
  }
}
