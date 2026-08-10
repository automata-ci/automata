import {
  validateRepository,
  validateRepositoryShell,
  validateShell,
} from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectGeneratedCsrfToken,
  expectLiteral,
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  invalid,
} from "./primitives";

const MAX_I64_DECIMAL = "9223372036854775807";
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,19}$/u;
const PUBLICATION_AUDIENCES = [
  "private",
  "authenticated",
  "public",
] as const;

export function validateRepositorySettingsPage(
  value: unknown,
  path: string,
): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "heading",
    "summary",
    "settingsNavigation",
    "revision",
    "policy",
    "update",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "repository-settings");
  const shellContext = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(
    page.repository,
    `${path}.repository`,
  );
  if (repository.settingsHref === null) {
    invalid(
      `${path}.repository.settingsHref`,
      "an authorized settings destination for this page",
    );
  }
  validateRepositoryShell(repository, shellContext, path);
  validateRepositorySettingsNavigation(
    page.settingsNavigation,
    `${path}.settingsNavigation`,
    repository,
    "access",
  );
  expectTextField(page, "heading", path);
  expectTextField(
    page,
    "summary",
    path,
    RENDER_REQUEST_LIMITS.longTextLength,
  );
  const revision = validatePositiveRevision(page.revision, `${path}.revision`);
  validatePublicationPolicy(page.policy, `${path}.policy`);
  if (page.update !== null) {
    if (revision === MAX_I64_DECIMAL) {
      invalid(`${path}.revision`, "a revision that can be advanced by an update");
    }
    validateUpdateCapability(
      page.update,
      `${path}.update`,
      repository.settingsHref,
    );
  }
}

export function validatePositiveRevision(value: unknown, path: string): string {
  const revision = expectString(value, path, MAX_I64_DECIMAL.length, 1);
  if (
    !POSITIVE_DECIMAL.test(revision) ||
    (revision.length === MAX_I64_DECIMAL.length && revision > MAX_I64_DECIMAL)
  ) {
    invalid(path, "a lossless positive decimal publication revision");
  }
  return revision;
}

export function validateRepositorySettingsNavigation(
  value: unknown,
  path: string,
  repository: {
    readonly owner: string;
    readonly name: string;
    readonly settingsHref: string | null;
  },
  expectedCurrent: "access" | "secrets",
): void {
  const navigation = expectObject(value, path, [
    "accessHref",
    "secretsHref",
    "current",
  ]);
  const accessHref = expectNullableRoute(
    navigation.accessHref,
    `${path}.accessHref`,
  );
  const secretsHref = expectNullableRoute(
    navigation.secretsHref,
    `${path}.secretsHref`,
  );
  const current = expectOneOf(navigation.current, `${path}.current`, [
    "access",
    "secrets",
  ]);
  if (current !== expectedCurrent) {
    invalid(`${path}.current`, `the current ${expectedCurrent} settings area`);
  }
  const root = `/${repository.owner}/${repository.name}/settings`;
  if (accessHref !== null && accessHref !== `${root}/access`) {
    invalid(`${path}.accessHref`, "the canonical repository access destination");
  }
  if (secretsHref !== null && secretsHref !== `${root}/secrets`) {
    invalid(`${path}.secretsHref`, "the canonical repository secrets destination");
  }
  if (
    (current === "access" && accessHref === null) ||
    (current === "secrets" && secretsHref === null)
  ) {
    invalid(`${path}.${current}Href`, "a destination for the current settings area");
  }
  const preferredSettingsHref = accessHref ?? secretsHref;
  if (
    preferredSettingsHref === null ||
    repository.settingsHref !== preferredSettingsHref
  ) {
    invalid(
      `${path}.accessHref`,
      "the first authorized repository settings destination",
    );
  }
}

function validatePublicationPolicy(value: unknown, path: string): void {
  const policy = expectObject(value, path, [
    "dashboard",
    "logs",
    "artifacts",
  ]);
  for (const field of ["dashboard", "logs", "artifacts"] as const) {
    expectOneOf(policy[field], `${path}.${field}`, PUBLICATION_AUDIENCES);
  }
}

function validateUpdateCapability(
  value: unknown,
  path: string,
  settingsHref: string,
): void {
  const update = expectObject(value, path, ["action", "csrfToken"]);
  const action = expectRouteField(update, "action", path);
  if (action !== settingsHref) {
    invalid(`${path}.action`, "the repository settings destination");
  }
  expectGeneratedCsrfToken(update.csrfToken, `${path}.csrfToken`);
}
