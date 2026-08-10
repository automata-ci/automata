import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectBoolean,
  expectDisplayText,
  expectGeneratedCsrfToken,
  expectGitHubScmUrl,
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  hasOwn,
  invalid,
} from "./primitives";

const MAX_U64_DECIMAL = "18446744073709551615";
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,19}$/u;
const PULL_REQUEST_REF = /^pull\/([1-9][0-9]{0,19})\/(?:head|merge)$/u;
const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/u;

export interface RepositoryContext {
  readonly owner: string;
  readonly name: string;
  readonly runsHref: string;
  readonly settingsHref: string | null;
}

export interface StatusContext {
  readonly label: string;
  readonly tone: "neutral" | "queued" | "running" | "success" | "failure" | "warning";
}

interface ShellContext {
  readonly authenticated: boolean;
  readonly homeHref: string;
  readonly navigation: readonly {
    readonly label: string;
    readonly href: string;
    readonly current: boolean;
  }[];
}

const STATUS_TONE_BY_LABEL: Readonly<Record<string, StatusContext["tone"]>> = {
  Cancelled: "neutral",
  Failed: "failure",
  "In progress": "running",
  Lost: "warning",
  Queued: "queued",
  Skipped: "neutral",
  Succeeded: "success",
  "Timed out": "failure",
};

export function validateShell(value: unknown, path: string): ShellContext {
  const shell = expectObject(value, path, [
    "productName",
    "homeHref",
    "signIn",
    "signOut",
    "documentTitle",
    "description",
    "viewer",
    "navigation",
  ]);
  expectTextField(shell, "productName", path);
  const homeHref = expectRouteField(shell, "homeHref", path);
  const signInPath = `${path}.signIn`;
  let hasSignIn = false;
  if (shell.signIn !== null) {
    const signIn = expectObject(shell.signIn, signInPath, ["action", "returnPath"]);
    const action = expectRouteField(signIn, "action", signInPath);
    if (action !== "/auth/github/login") {
      invalid(`${signInPath}.action`, 'the canonical "/auth/github/login" action');
    }
    const returnPath = expectRouteField(signIn, "returnPath", signInPath);
    expectString(returnPath, `${signInPath}.returnPath`, 2_048, 1);
    if (!returnPath.startsWith("/") || returnPath.startsWith("//")) {
      invalid(`${signInPath}.returnPath`, "a bounded rooted local return path");
    }
    hasSignIn = true;
  }
  const signOutPath = `${path}.signOut`;
  let hasSignOut = false;
  if (shell.signOut !== null) {
    const signOut = expectObject(shell.signOut, signOutPath, ["action", "csrfToken"]);
    const action = expectRouteField(signOut, "action", signOutPath);
    if (action !== "/auth/logout") {
      invalid(`${signOutPath}.action`, 'the canonical "/auth/logout" action');
    }
    expectGeneratedCsrfToken(signOut.csrfToken, `${signOutPath}.csrfToken`);
    hasSignOut = true;
  }
  expectTextField(shell, "documentTitle", path);
  expectTextField(shell, "description", path, RENDER_REQUEST_LIMITS.longTextLength);

  if (shell.viewer !== null) {
    const viewerPath = `${path}.viewer`;
    const viewer = expectObject(shell.viewer, viewerPath, ["displayName"]);
    expectTextField(viewer, "displayName", viewerPath);
    if (hasSignIn) {
      invalid(signInPath, "null for an authenticated viewer");
    }
  } else if (hasSignOut) {
    invalid(signOutPath, "null for an anonymous viewer");
  }

  const navigationPath = `${path}.navigation`;
  const navigation = expectArray(
    shell.navigation,
    navigationPath,
    RENDER_REQUEST_LIMITS.navigationCount,
  );
  if (navigation.length === 0) {
    invalid(navigationPath, "at least one primary navigation item");
  }
  const seenHrefs = new Set<string>();
  const validatedNavigation: Array<{
    readonly label: string;
    readonly href: string;
    readonly current: boolean;
  }> = [];
  let currentItemCount = 0;
  navigation.forEach((item, index) => {
    const itemPath = `${navigationPath}[${index}]`;
    const navigationItem = expectObject(item, itemPath, ["label", "href"], ["current"]);
    const label = expectTextField(navigationItem, "label", itemPath);
    const href = expectRouteField(navigationItem, "href", itemPath);
    expectUnique(seenHrefs, href, `${itemPath}.href`);
    if (hasOwn(navigationItem, "current")) {
      expectBoolean(navigationItem.current, `${itemPath}.current`);
      if (navigationItem.current === true) {
        currentItemCount += 1;
      }
    }
    validatedNavigation.push({
      label,
      href,
      current: navigationItem.current === true,
    });
  });
  if (currentItemCount !== 1) {
    invalid(navigationPath, "exactly one current primary navigation item");
  }
  return {
    authenticated: shell.viewer !== null,
    homeHref,
    navigation: validatedNavigation,
  };
}

export function validateRepositoryShell(
  repository: RepositoryContext,
  shell: ShellContext,
  path: string,
): void {
  if (repository.settingsHref !== null && !shell.authenticated) {
    invalid(`${path}.repository.settingsHref`, "null for an anonymous viewer");
  }
  const [repositoriesNavigation, actionsNavigation, accessNavigation] = shell.navigation;
  if (
    shell.homeHref !== "/repositories" ||
    (shell.navigation.length !== 2 && shell.navigation.length !== 3) ||
    repositoriesNavigation?.label !== "Repositories" ||
    repositoriesNavigation.href !== "/repositories" ||
    repositoriesNavigation.current ||
    actionsNavigation?.label !== "Actions" ||
    actionsNavigation.href !== repository.runsHref ||
    !actionsNavigation.current ||
    (accessNavigation !== undefined &&
      (accessNavigation.label !== "Access" ||
        accessNavigation.href !== "/settings/access/users" ||
        accessNavigation.current))
  ) {
    invalid(
      `${path}.shell.navigation`,
      "coherent Repositories, current Actions, and optional Access navigation",
    );
  }
}

export function validateRepository(value: unknown, path: string): RepositoryContext {
  const repository = expectObject(value, path, [
    "owner",
    "name",
    "sourceHref",
    "runsHref",
    "settingsHref",
  ]);
  const owner = expectString(
    repository.owner,
    `${path}.owner`,
    RENDER_REQUEST_LIMITS.shortTextLength,
    1,
  );
  const name = expectString(
    repository.name,
    `${path}.name`,
    RENDER_REQUEST_LIMITS.shortTextLength,
    1,
  );
  expectGitHubScmUrl(repository.sourceHref, `${path}.sourceHref`, owner, name, {
    kind: "repository",
  });
  const runsHref = expectRouteField(repository, "runsHref", path);
  const settingsHref = expectNullableRoute(
    repository.settingsHref,
    `${path}.settingsHref`,
  );
  if (settingsHref === runsHref) {
    invalid(`${path}.settingsHref`, "a destination distinct from runsHref");
  }
  return { owner, name, runsHref, settingsHref };
}

export function validatePagination(value: unknown, path: string): void {
  const pagination = expectObject(value, path, ["previousHref", "nextHref", "label"]);
  const previousHref = expectNullableRoute(
    pagination.previousHref,
    `${path}.previousHref`,
  );
  const nextHref = expectNullableRoute(pagination.nextHref, `${path}.nextHref`);
  if (previousHref !== null && previousHref === nextHref) {
    invalid(`${path}.nextHref`, "a destination distinct from previousHref");
  }
  expectTextField(pagination, "label", path);
}

export function validateCommit(
  value: unknown,
  path: string,
  repository: RepositoryContext,
): void {
  const commit = expectObject(value, path, ["shortSha", "message", "href"]);
  const shortSha = expectString(commit.shortSha, `${path}.shortSha`, 64, 4);
  if (!/^[a-f0-9]+$/u.test(shortSha)) {
    invalid(`${path}.shortSha`, "a canonical lowercase commit identifier");
  }
  if (commit.message !== null) {
    expectDisplayText(commit.message, `${path}.message`);
  }
  expectGitHubScmUrl(
    commit.href,
    `${path}.href`,
    repository.owner,
    repository.name,
    { kind: "commit", shortSha },
  );
}

export function validateSourceRef(
  value: unknown,
  path: string,
  repository: RepositoryContext,
): void {
  if (value === null) {
    return;
  }

  const sourceRef = expectObject(value, path, ["name", "kind", "href"]);
  const name = expectDisplayText(
    sourceRef.name,
    `${path}.name`,
    RENDER_REQUEST_LIMITS.shortTextLength,
  );
  const kind = expectOneOf(sourceRef.kind, `${path}.kind`, [
    "branch",
    "tag",
    "ref",
  ]);

  if (kind === "branch" || kind === "tag") {
    expectGitHubScmUrl(
      sourceRef.href,
      `${path}.href`,
      repository.owner,
      repository.name,
      { kind: "tree", refName: name },
    );
    return;
  }

  if (kind === "ref") {
    const match = PULL_REQUEST_REF.exec(name);
    const pullNumber = match?.[1];
    if (
      pullNumber === undefined ||
      (pullNumber.length === MAX_U64_DECIMAL.length &&
        pullNumber > MAX_U64_DECIMAL)
    ) {
      invalid(`${path}.name`, 'a pull request ref such as "pull/42/merge"');
    }
    expectGitHubScmUrl(
      sourceRef.href,
      `${path}.href`,
      repository.owner,
      repository.name,
      { kind: "pull", pullNumber },
    );
    return;
  }
}

export function validateStatus(value: unknown, path: string): StatusContext {
  const status = expectObject(value, path, ["label", "tone"]);
  const label = expectTextField(status, "label", path);
  const tone = expectOneOf(status.tone, `${path}.tone`, [
    "neutral",
    "queued",
    "running",
    "success",
    "failure",
    "warning",
  ]);
  const expectedTone = STATUS_TONE_BY_LABEL[label];
  if (expectedTone === undefined) {
    invalid(`${path}.label`, "a current workflow status label");
  }
  if (tone !== expectedTone) {
    invalid(`${path}.tone`, "the tone paired with this workflow status label");
  }
  return { label, tone };
}

export function validateTimestamp(value: unknown, path: string): void {
  const timestamp = expectObject(value, path, ["iso", "label"]);
  const iso = expectString(timestamp.iso, `${path}.iso`, 64, 20);
  if (!isValidRfc3339Timestamp(iso)) {
    invalid(`${path}.iso`, "an RFC 3339 timestamp");
  }
  expectTextField(timestamp, "label", path);
}

function isValidRfc3339Timestamp(value: string): boolean {
  const match = RFC3339_TIMESTAMP.exec(value);
  if (match === null) {
    return false;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[7] === undefined ? 0 : Number(match[7]);
  const offsetMinute = match[8] === undefined ? 0 : Number(match[8]);
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth(year, month) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    offsetHour <= 23 &&
    offsetMinute <= 59
  );
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leapYear ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/** Validates a positive u64 without converting it to an imprecise JS number. */
export function validateRunNumber(value: unknown, path: string): void {
  const number = expectString(value, path, MAX_U64_DECIMAL.length, 1);
  if (
    !POSITIVE_DECIMAL.test(number) ||
    (number.length === MAX_U64_DECIMAL.length && number > MAX_U64_DECIMAL)
  ) {
    invalid(path, "a lossless positive decimal run number");
  }
}
