import {
  validateRepository,
  validateRepositoryShell,
  validateShell,
  validateTimestamp,
} from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectGeneratedCsrfToken,
  expectInteger,
  expectLiteral,
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  invalid,
  type JsonRecord,
} from "./primitives";
import {
  validatePositiveRevision,
  validateRepositorySettingsNavigation,
} from "./repositorySettingsModel";

const BUILTIN_PROVIDER_ID = "builtin";
const MAX_SECRET_VALUE_BYTES = 65_536;
const MAX_U64_DECIMAL = "18446744073709551615";
const POSITIVE_U64 = /^[1-9][0-9]{0,19}$/u;
const CANONICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const SECRET_NAME = /^[A-Z_][A-Z0-9_]{0,254}$/u;
const RESERVED_SECRET_PREFIXES = [
  "GITHUB_",
  "ACTIONS_",
  "RUNNER_",
  "AUTOMATA_",
] as const;

interface MutationEvidence {
  authorizationRevision: string | null;
  csrfToken: string | null;
}

export function validateRepositorySecretsPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "heading",
    "summary",
    "settingsNavigation",
    "notice",
    "maximumValueBytes",
    "provider",
    "create",
    "secrets",
    "pagination",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "repository-secrets");
  const shellContext = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(page.repository, `${path}.repository`);
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
    "secrets",
  );
  expectTextField(page, "heading", path);
  expectTextField(page, "summary", path, RENDER_REQUEST_LIMITS.longTextLength);
  if (page.notice !== null) {
    expectOneOf(page.notice, `${path}.notice`, [
      "created",
      "replaced",
      "deleted",
      "provider-activated",
      "conflict",
    ]);
  }
  const maximumValueBytes = expectInteger(
    page.maximumValueBytes,
    `${path}.maximumValueBytes`,
    1,
    MAX_SECRET_VALUE_BYTES,
  );
  if (maximumValueBytes !== MAX_SECRET_VALUE_BYTES) {
    invalid(
      `${path}.maximumValueBytes`,
      "the exact secret-ingress byte limit",
    );
  }

  const secretRoot = `/${repository.owner}/${repository.name}/settings/secrets`;
  const mutationEvidence: MutationEvidence = {
    authorizationRevision: null,
    csrfToken: null,
  };
  const seenUuids = new Set<string>();
  if (page.provider !== null) {
    validateProvider(
      page.provider,
      `${path}.provider`,
      secretRoot,
      mutationEvidence,
    );
  }
  if (page.create !== null) {
    validateCreate(
      page.create,
      `${path}.create`,
      secretRoot,
      mutationEvidence,
      seenUuids,
    );
  }

  const secrets = expectArray(
    page.secrets,
    `${path}.secrets`,
    RENDER_REQUEST_LIMITS.secretCount,
  );
  const seenNames = new Set<string>();
  let previousId: string | null = null;
  secrets.forEach((secret, index) => {
    const secretPath = `${path}.secrets[${index}]`;
    const { id, name } = validateSecret(
      secret,
      secretPath,
      secretRoot,
      mutationEvidence,
      seenUuids,
    );
    expectUnique(seenNames, name, `${secretPath}.name`);
    if (previousId !== null && id <= previousId) {
      invalid(`${secretPath}.id`, "a strictly increasing secret identifier");
    }
    previousId = id;
  });
  validatePagination(
    page.pagination,
    `${path}.pagination`,
    secretRoot,
    secrets.length,
    previousId,
  );
}

function validateProvider(
  value: unknown,
  path: string,
  secretRoot: string,
  mutationEvidence: MutationEvidence,
): void {
  const provider = expectObject(value, path, [
    "id",
    "state",
    "health",
    "activation",
  ]);
  const id = expectString(provider.id, `${path}.id`, 64, 1);
  if (id !== BUILTIN_PROVIDER_ID) {
    invalid(`${path}.id`, "the composed built-in secret provider");
  }
  const state = expectOneOf(provider.state, `${path}.state`, [
    "unconfigured",
    "active",
    "disabled",
  ]);
  expectOneOf(provider.health, `${path}.health`, [
    "unknown",
    "healthy",
    "degraded",
    "unavailable",
  ]);
  if (provider.activation !== null) {
    if (state === "active") {
      invalid(`${path}.activation`, "null for an active provider");
    }
    const activationPath = `${path}.activation`;
    const activation = expectObject(provider.activation, activationPath, [
      "action",
      "csrfToken",
      "expectedAuthorizationRevision",
      "expectedRevision",
    ]);
    validateMutationEnvelope(
      activation,
      activationPath,
      `${secretRoot}/provider/activate`,
      mutationEvidence,
    );
    const expectedRevision = validatePositiveRevision(
      activation.expectedRevision,
      `${activationPath}.expectedRevision`,
    );
    if (expectedRevision === "9223372036854775807") {
      invalid(
        `${activationPath}.expectedRevision`,
        "a provider revision that can be advanced by activation",
      );
    }
  }
}

function validateCreate(
  value: unknown,
  path: string,
  secretRoot: string,
  mutationEvidence: MutationEvidence,
  seenUuids: Set<string>,
): void {
  const create = expectObject(value, path, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "secretId",
    "mutationId",
  ]);
  validateMutationEnvelope(create, path, secretRoot, mutationEvidence);
  expectUnique(
    seenUuids,
    validateUuid(create.secretId, `${path}.secretId`),
    `${path}.secretId`,
  );
  expectUnique(
    seenUuids,
    validateUuid(create.mutationId, `${path}.mutationId`),
    `${path}.mutationId`,
  );
}

function validateSecret(
  value: unknown,
  path: string,
  secretRoot: string,
  mutationEvidence: MutationEvidence,
  seenUuids: Set<string>,
): { readonly id: string; readonly name: string } {
  const secret = expectObject(value, path, [
    "id",
    "name",
    "providerId",
    "state",
    "currentVersion",
    "revision",
    "updatedAt",
    "replace",
    "delete",
  ]);
  const id = validateUuid(secret.id, `${path}.id`);
  expectUnique(seenUuids, id, `${path}.id`);
  const name = validateSecretName(secret.name, `${path}.name`);
  const providerId = expectString(secret.providerId, `${path}.providerId`, 64, 1);
  if (providerId !== BUILTIN_PROVIDER_ID) {
    invalid(`${path}.providerId`, "the composed built-in secret provider");
  }
  const state = expectOneOf(secret.state, `${path}.state`, [
    "provisioning",
    "active",
    "disabled",
  ]);
  const currentVersion = secret.currentVersion === null
    ? null
    : validatePositiveU64(secret.currentVersion, `${path}.currentVersion`);
  const revision = validatePositiveRevision(secret.revision, `${path}.revision`);
  validateTimestamp(secret.updatedAt, `${path}.updatedAt`);
  if (
    (state === "provisioning" && currentVersion !== null) ||
    (state !== "provisioning" && currentVersion === null)
  ) {
    invalid(`${path}.currentVersion`, "a version coherent with the secret state");
  }

  if (secret.replace !== null) {
    if (state !== "active") {
      invalid(`${path}.replace`, "null unless the secret is active");
    }
    const replacePath = `${path}.replace`;
    const replace = expectObject(secret.replace, replacePath, [
      "action",
      "csrfToken",
      "expectedAuthorizationRevision",
      "mutationId",
    ]);
    validateMutationEnvelope(
      replace,
      replacePath,
      `${secretRoot}/${id}/replace`,
      mutationEvidence,
    );
    expectUnique(
      seenUuids,
      validateUuid(replace.mutationId, `${replacePath}.mutationId`),
      `${replacePath}.mutationId`,
    );
  }
  if (secret.delete !== null) {
    const deletePath = `${path}.delete`;
    const deletion = expectObject(secret.delete, deletePath, [
      "action",
      "csrfToken",
      "expectedAuthorizationRevision",
    ]);
    validateMutationEnvelope(
      deletion,
      deletePath,
      `${secretRoot}/${id}/delete`,
      mutationEvidence,
    );
  }
  if (revision === "9223372036854775807" && secret.replace !== null) {
    invalid(`${path}.replace`, "null at the maximum durable revision");
  }
  if (revision === "9223372036854775807" && secret.delete !== null) {
    invalid(`${path}.delete`, "null at the maximum durable revision");
  }
  return { id, name };
}

function validateMutationEnvelope(
  mutation: JsonRecord,
  path: string,
  expectedAction: string,
  evidence: MutationEvidence,
): void {
  const action = expectRouteField(mutation, "action", path);
  if (action !== expectedAction) {
    invalid(`${path}.action`, "the exact repository-secret mutation destination");
  }
  const csrfToken = expectGeneratedCsrfToken(mutation.csrfToken, `${path}.csrfToken`);
  const authorizationRevision = validatePositiveRevision(
    mutation.expectedAuthorizationRevision,
    `${path}.expectedAuthorizationRevision`,
  );
  if (evidence.csrfToken !== null && csrfToken !== evidence.csrfToken) {
    invalid(`${path}.csrfToken`, "the page's single CSRF proof");
  }
  if (
    evidence.authorizationRevision !== null &&
    authorizationRevision !== evidence.authorizationRevision
  ) {
    invalid(
      `${path}.expectedAuthorizationRevision`,
      "the page's single authorization revision",
    );
  }
  evidence.csrfToken = csrfToken;
  evidence.authorizationRevision = authorizationRevision;
}

function validatePagination(
  value: unknown,
  path: string,
  secretRoot: string,
  count: number,
  lastId: string | null,
): void {
  const pagination = expectObject(value, path, [
    "firstHref",
    "nextHref",
    "label",
  ]);
  const firstHref = expectNullableRoute(pagination.firstHref, `${path}.firstHref`);
  if (firstHref !== null && firstHref !== secretRoot) {
    invalid(`${path}.firstHref`, "the first repository-secret page");
  }
  const nextHref = expectNullableRoute(pagination.nextHref, `${path}.nextHref`);
  const expectedNextHref = lastId === null ? null : `${secretRoot}?after=${lastId}`;
  if (
    nextHref !== null &&
    (count !== RENDER_REQUEST_LIMITS.secretCount || nextHref !== expectedNextHref)
  ) {
    invalid(`${path}.nextHref`, "the next value-free secret metadata page");
  }
  const label = expectTextField(pagination, "label", path);
  const expectedLabel = `${count} ${count === 1 ? "secret" : "secrets"}`;
  if (label !== expectedLabel) {
    invalid(`${path}.label`, "the exact visible secret count");
  }
}

function validateUuid(value: unknown, path: string): string {
  const id = expectString(value, path, 36, 36);
  if (!CANONICAL_UUID.test(id) || id === NIL_UUID) {
    invalid(path, "a canonical lowercase non-nil UUID");
  }
  return id;
}

function validateSecretName(value: unknown, path: string): string {
  const name = expectString(value, path, 255, 1);
  if (
    !SECRET_NAME.test(name) ||
    RESERVED_SECRET_PREFIXES.some((prefix) => name.startsWith(prefix))
  ) {
    invalid(path, "a canonical, non-reserved repository secret name");
  }
  return name;
}

function validatePositiveU64(value: unknown, path: string): string {
  const decimal = expectString(value, path, MAX_U64_DECIMAL.length, 1);
  if (
    !POSITIVE_U64.test(decimal) ||
    (decimal.length === MAX_U64_DECIMAL.length && decimal > MAX_U64_DECIMAL)
  ) {
    invalid(path, "a lossless positive decimal version");
  }
  return decimal;
}
