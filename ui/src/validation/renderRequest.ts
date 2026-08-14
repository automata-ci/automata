import type { RenderRequest } from "../models";
import { validateJobLogPage } from "./jobLogModel";
import { validateDeepLinkSignInPage } from "./deepLinkSignInModel";
import { validateRepositoryDirectoryPage } from "./repositoryDirectoryModel";
import { validateRepositorySettingsPage } from "./repositorySettingsModel";
import { validateRepositorySecretsPage } from "./repositorySecretsModel";
import {
  validateDirectBindingListPage,
  validateRoleDetailPage,
  validateRoleListPage,
  validateUserDetailPage,
  validateUserListPage,
} from "./rbacManagementModels";
import { validateRunDetailPage } from "./runDetailModel";
import { validateRunListPage } from "./runListModel";
import { validateSetupPage } from "./setupPageModel";
import {
  expectArray,
  expectAssetPath,
  expectLiteral,
  expectObject,
  expectRecord,
  expectString,
  expectUnique,
  field,
  invalid,
} from "./primitives";
import {
  MAX_SERIALIZED_RENDER_REQUEST_BYTES,
  RENDER_REQUEST_LIMITS,
  utf8ByteLength,
} from "./limits";

/** Validate every field before the model reaches an HTML or URL sink. */
export function validateRenderRequest(value: unknown): RenderRequest {
  const request = expectObject(value, "$", ["schemaVersion", "host", "page"]);
  expectLiteral(field(request, "schemaVersion", "$"), "$.schemaVersion", 1);
  validateHost(field(request, "host", "$"), "$.host");
  validatePage(field(request, "page", "$"), "$.page");
  const serialized = JSON.stringify(value);
  if (utf8ByteLength(serialized) > MAX_SERIALIZED_RENDER_REQUEST_BYTES) {
    invalid("$", `at most ${MAX_SERIALIZED_RENDER_REQUEST_BYTES} serialized UTF-8 bytes`);
  }
  return value as RenderRequest;
}

function validateHost(value: unknown, path: string): void {
  const host = expectObject(value, path, ["locale", "assets", "cspNonce"]);
  const locale = expectString(field(host, "locale", path), `${path}.locale`, 2, 2);
  if (locale !== "en") {
    invalid(`${path}.locale`, 'the current supported locale "en"');
  }

  const assetsPath = `${path}.assets`;
  const assets = expectObject(field(host, "assets", path), assetsPath, [
    "clientEntry",
    "stylesheets",
  ]);
  expectAssetPath(
    field(assets, "clientEntry", assetsPath),
    `${assetsPath}.clientEntry`,
    "client-script",
  );

  const stylesheetsPath = `${assetsPath}.stylesheets`;
  const stylesheets = expectArray(
    field(assets, "stylesheets", assetsPath),
    stylesheetsPath,
    RENDER_REQUEST_LIMITS.stylesheetCount,
  );
  const seenStylesheets = new Set<string>();
  stylesheets.forEach((stylesheet, index) => {
    const itemPath = `${stylesheetsPath}[${index}]`;
    const pathValue = expectAssetPath(stylesheet, itemPath, "stylesheet");
    expectUnique(seenStylesheets, pathValue, itemPath);
  });

  const nonce = expectString(field(host, "cspNonce", path), `${path}.cspNonce`, 256, 1);
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(nonce)) {
    invalid(`${path}.cspNonce`, "a base64 or base64url CSP nonce");
  }
}

function validatePage(value: unknown, path: string): void {
  const page = expectRecord(value, path);
  const kind = field(page, "kind", path);
  if (kind === "setup") {
    validateSetupPage(page, path);
  } else if (kind === "repository-directory") {
    validateRepositoryDirectoryPage(page, path);
  } else if (kind === "run-list") {
    validateRunListPage(page, path);
  } else if (kind === "run-detail") {
    validateRunDetailPage(page, path);
  } else if (kind === "job-log") {
    validateJobLogPage(page, path);
  } else if (kind === "deep-link-sign-in") {
    validateDeepLinkSignInPage(page, path);
  } else if (kind === "repository-settings") {
    validateRepositorySettingsPage(page, path);
  } else if (kind === "repository-secrets") {
    validateRepositorySecretsPage(page, path);
  } else if (kind === "user-list") {
    validateUserListPage(page, path);
  } else if (kind === "user-detail") {
    validateUserDetailPage(page, path);
  } else if (kind === "role-list") {
    validateRoleListPage(page, path);
  } else if (kind === "role-detail") {
    validateRoleDetailPage(page, path);
  } else if (kind === "direct-binding-list") {
    validateDirectBindingListPage(page, path);
  } else {
    invalid(
      `${path}.kind`,
      'a current supported page kind',
    );
  }
}
