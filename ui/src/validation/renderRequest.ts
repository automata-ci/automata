import type { RenderRequest } from "../models";
import { validateRunDetailPage } from "./runDetailModel";
import { validateRunListPage } from "./runListModel";
import {
  expectArray,
  expectAssetPath,
  expectLiteral,
  expectObject,
  expectRecord,
  expectString,
  expectUnique,
  field,
  hasOwn,
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
  const host = expectObject(value, path, ["locale", "assets"], ["cspNonce"]);
  const locale = expectString(field(host, "locale", path), `${path}.locale`, 35, 2);
  if (!/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/u.test(locale)) {
    invalid(`${path}.locale`, "a structurally valid BCP 47 language tag");
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

  if (hasOwn(host, "cspNonce")) {
    const nonce = expectString(host.cspNonce, `${path}.cspNonce`, 256, 1);
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(nonce)) {
      invalid(`${path}.cspNonce`, "a base64 or base64url CSP nonce");
    }
  }
}

function validatePage(value: unknown, path: string): void {
  const page = expectRecord(value, path);
  const kind = field(page, "kind", path);
  if (kind === "run-list") {
    validateRunListPage(page, path);
  } else if (kind === "run-detail") {
    validateRunDetailPage(page, path);
  } else {
    invalid(`${path}.kind`, '"run-list" or "run-detail"');
  }
}
