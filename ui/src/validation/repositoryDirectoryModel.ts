import { validateShell } from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectGitHubScmUrl,
  expectLiteral,
  expectNullableRoute,
  expectObject,
  expectString,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

const REPOSITORIES_PATH = "/repositories";
const CURSOR_PATTERN = /^[A-Za-z0-9_-]{1,512}$/u;

export function validateRepositoryDirectoryPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "heading",
    "summary",
    "repositories",
    "pagination",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "repository-directory");
  const shell = validateShell(page.shell, `${path}.shell`);
  if (shell.homeHref !== REPOSITORIES_PATH) {
    invalid(`${path}.shell.homeHref`, "the canonical repository directory");
  }
  const [repositoriesNavigation, accessNavigation] = shell.navigation;
  if (
    shell.navigation.length > 2 ||
    repositoriesNavigation?.label !== "Repositories" ||
    repositoriesNavigation.href !== REPOSITORIES_PATH ||
    !repositoriesNavigation.current ||
    (accessNavigation !== undefined &&
      (accessNavigation.label !== "Access" ||
        accessNavigation.href !== "/settings/access/users" ||
        accessNavigation.current))
  ) {
    invalid(`${path}.shell.navigation`, "current Repositories and optional Access navigation");
  }
  expectTextField(page, "heading", path);
  expectTextField(page, "summary", path, RENDER_REQUEST_LIMITS.longTextLength);

  const repositoriesPath = `${path}.repositories`;
  const repositories = expectArray(
    page.repositories,
    repositoriesPath,
    RENDER_REQUEST_LIMITS.repositoryCount,
  );
  const seenCoordinates = new Set<string>();
  const seenDestinations = new Set<string>();
  repositories.forEach((value, index) => {
    const itemPath = `${repositoriesPath}[${index}]`;
    const item = expectObject(value, itemPath, [
      "owner",
      "name",
      "sourceHref",
      "actionsHref",
      "settingsHref",
    ]);
    const owner = expectString(
      item.owner,
      `${itemPath}.owner`,
      RENDER_REQUEST_LIMITS.shortTextLength,
      1,
    );
    const name = expectString(
      item.name,
      `${itemPath}.name`,
      RENDER_REQUEST_LIMITS.shortTextLength,
      1,
    );
    expectUnique(
      seenCoordinates,
      `${owner.toLowerCase()}/${name.toLowerCase()}`,
      `${itemPath}.name`,
    );
    const sourceHref = expectGitHubScmUrl(
      item.sourceHref,
      `${itemPath}.sourceHref`,
      owner,
      name,
      { kind: "repository" },
    );
    expectUnique(seenDestinations, sourceHref, `${itemPath}.sourceHref`);
    const repositoryRoot = `/${owner}/${name}`;
    const actionsHref = expectNullableRoute(item.actionsHref, `${itemPath}.actionsHref`);
    if (actionsHref !== null) {
      if (actionsHref !== `${repositoryRoot}/actions`) {
        invalid(`${itemPath}.actionsHref`, "the exact repository Actions destination");
      }
      expectUnique(seenDestinations, actionsHref, `${itemPath}.actionsHref`);
    }
    const settingsHref = expectNullableRoute(item.settingsHref, `${itemPath}.settingsHref`);
    if (settingsHref !== null) {
      if (!shell.authenticated) {
        invalid(`${itemPath}.settingsHref`, "null for an anonymous viewer");
      }
      if (
        settingsHref !== `${repositoryRoot}/settings/access` &&
        settingsHref !== `${repositoryRoot}/settings/secrets`
      ) {
        invalid(
          `${itemPath}.settingsHref`,
          "an exact authorized repository settings destination",
        );
      }
      expectUnique(seenDestinations, settingsHref, `${itemPath}.settingsHref`);
    }
  });

  const paginationPath = `${path}.pagination`;
  const pagination = expectObject(page.pagination, paginationPath, ["nextHref", "label"]);
  const nextHref = expectNullableRoute(pagination.nextHref, `${paginationPath}.nextHref`);
  if (nextHref !== null) {
    const prefix = `${REPOSITORIES_PATH}?cursor=`;
    const cursor = nextHref.startsWith(prefix) ? nextHref.slice(prefix.length) : "";
    if (!CURSOR_PATTERN.test(cursor)) {
      invalid(`${paginationPath}.nextHref`, "a canonical next repository page");
    }
  }
  const label = expectTextField(pagination, "label", paginationPath);
  const expectedLabel = `${repositories.length} ${repositories.length === 1 ? "repository" : "repositories"} on this page`;
  if (label !== expectedLabel) {
    invalid(`${paginationPath}.label`, "the exact visible repository count");
  }
}
