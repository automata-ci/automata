import {
  validateShell,
  validateTimestamp,
} from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectBoolean,
  expectDisplayText,
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

const USERS_PATH = "/settings/access/users";
const ROLES_PATH = "/settings/access/roles";
const DIRECT_BINDINGS_PATH = "/settings/access/direct-bindings";
const CANONICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const POLICY_NAME = /^[A-Za-z0-9_.:-]{1,128}$/u;
const POSITIVE_REVISION = /^[1-9][0-9]{0,18}$/u;
const MAX_I64 = "9223372036854775807";

type ManagementArea = "users" | "roles" | "direct-bindings";

export function validateUserListPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "managementNav",
    "heading",
    "summary",
    "users",
    "notice",
    "pagination",
  ]);
  validateManagementPageHeader(page, path, "user-list", "users");

  const usersPath = `${path}.users`;
  const users = expectArray(
    page.users,
    usersPath,
    RENDER_REQUEST_LIMITS.userCount,
  );
  const seenIds = new Set<string>();
  const seenHrefs = new Set<string>();
  users.forEach((user, index) => {
    const userPath = `${usersPath}[${index}]`;
    const validated = validateManagedUser(user, userPath);
    expectUnique(seenIds, validated.id, `${userPath}.id`);
    expectUnique(seenHrefs, validated.href, `${userPath}.href`);
  });
  validateNotice(page.notice, `${path}.notice`);
  validateManagementPagination(
    page.pagination,
    `${path}.pagination`,
    USERS_PATH,
    "uuid",
  );
}

export function validateUserDetailPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "managementNav",
    "heading",
    "summary",
    "user",
    "roleAssignments",
    "notice",
    "statusUpdate",
  ]);
  validateManagementPageHeader(page, path, "user-detail", "users");
  const user = validateManagedUser(page.user, `${path}.user`);
  const expectedHeading = user.displayName ?? user.providerLogin;
  if (page.heading !== expectedHeading) {
    invalid(`${path}.heading`, "the displayed user identity");
  }
  validateNotice(page.notice, `${path}.notice`);
  validateMemberStatusUpdate(
    page.statusUpdate,
    `${path}.statusUpdate`,
    user.id,
    user.status,
  );

  const assignmentsPath = `${path}.roleAssignments`;
  const assignments = expectArray(
    page.roleAssignments,
    assignmentsPath,
    RENDER_REQUEST_LIMITS.bindingCount,
  );
  const seenBindingIds = new Set<string>();
  assignments.forEach((assignment, index) => {
    const assignmentPath = `${assignmentsPath}[${index}]`;
    const record = expectObject(assignment, assignmentPath, [
      "bindingId",
      "bindingHref",
      "roleId",
      "roleHref",
      "roleName",
      "roleDisplayName",
      "scope",
      "source",
      "status",
      "validUntil",
    ]);
    const bindingId = expectCanonicalUuid(
      record.bindingId,
      `${assignmentPath}.bindingId`,
    );
    const bindingHref = expectRouteField(
      record,
      "bindingHref",
      assignmentPath,
    );
    if (bindingHref !== DIRECT_BINDINGS_PATH) {
      invalid(
        `${assignmentPath}.bindingHref`,
        "the exact direct-binding list destination",
      );
    }
    const roleId = expectCanonicalUuid(
      record.roleId,
      `${assignmentPath}.roleId`,
    );
    const roleHref = expectRouteField(record, "roleHref", assignmentPath);
    if (roleHref !== `${ROLES_PATH}/${roleId}`) {
      invalid(
        `${assignmentPath}.roleHref`,
        "the exact role-detail destination",
      );
    }
    expectPolicyName(record.roleName, `${assignmentPath}.roleName`);
    expectDisplayText(
      record.roleDisplayName,
      `${assignmentPath}.roleDisplayName`,
      255,
    );
    validateScope(record.scope, `${assignmentPath}.scope`);
    expectOneOf(record.source, `${assignmentPath}.source`, [
      "direct",
      "provider-observed",
    ]);
    expectOneOf(record.status, `${assignmentPath}.status`, [
      "active",
      "revoked",
    ]);
    validateNullableTimestamp(
      record.validUntil,
      `${assignmentPath}.validUntil`,
    );
    expectUnique(
      seenBindingIds,
      bindingId,
      `${assignmentPath}.bindingId`,
    );
  });
}

export function validateRoleListPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "managementNav",
    "heading",
    "summary",
    "roles",
    "notice",
    "create",
    "pagination",
  ]);
  validateManagementPageHeader(page, path, "role-list", "roles");

  const rolesPath = `${path}.roles`;
  const roles = expectArray(
    page.roles,
    rolesPath,
    RENDER_REQUEST_LIMITS.roleCount,
  );
  const seenIds = new Set<string>();
  const seenHrefs = new Set<string>();
  const seenNames = new Set<string>();
  roles.forEach((role, index) => {
    const rolePath = `${rolesPath}[${index}]`;
    const validated = validateRoleSummary(role, rolePath);
    expectUnique(seenIds, validated.id, `${rolePath}.id`);
    expectUnique(seenHrefs, validated.href, `${rolePath}.href`);
    expectUnique(seenNames, validated.name, `${rolePath}.name`);
  });
  validateNotice(page.notice, `${path}.notice`);
  if (page.create !== null) {
    const createPath = `${path}.create`;
    const create = expectObject(page.create, createPath, [
      "action",
      "csrfToken",
      "expectedAuthorizationRevision",
    ]);
    validateMutationEnvelope(create, createPath, ROLES_PATH);
  }
  validateManagementPagination(
    page.pagination,
    `${path}.pagination`,
    ROLES_PATH,
    "uuid",
  );
}

export function validateRoleDetailPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "managementNav",
    "heading",
    "summary",
    "role",
    "permissions",
    "notice",
    "update",
    "delete",
  ]);
  validateManagementPageHeader(page, path, "role-detail", "roles");
  const role = validateRoleSummary(page.role, `${path}.role`);
  if (page.heading !== role.displayName) {
    invalid(`${path}.heading`, "the displayed role name");
  }
  validateNotice(page.notice, `${path}.notice`);
  const mutationRevision = validateRoleMutations(
    page,
    path,
    role.id,
    role.immutable,
  );

  const permissionsPath = `${path}.permissions`;
  const permissions = expectArray(
    page.permissions,
    permissionsPath,
    RENDER_REQUEST_LIMITS.permissionCount,
  );
  const seenNames = new Set<string>();
  let grantedCount = 0;
  permissions.forEach((permission, index) => {
    const permissionPath = `${permissionsPath}[${index}]`;
    const record = expectObject(permission, permissionPath, [
      "name",
      "description",
      "granted",
      "update",
    ]);
    const name = expectPolicyName(record.name, `${permissionPath}.name`);
    expectUnique(seenNames, name, `${permissionPath}.name`);
    expectDisplayText(
      record.description,
      `${permissionPath}.description`,
      RENDER_REQUEST_LIMITS.longTextLength,
    );
    expectBoolean(record.granted, `${permissionPath}.granted`);
    if (record.granted === true) {
      grantedCount += 1;
    }
    validatePermissionUpdate(
      record.update,
      `${permissionPath}.update`,
      role.id,
      name,
      record.granted === true,
      mutationRevision,
    );
  });
  if (grantedCount !== role.permissionCount) {
    invalid(
      `${path}.role.permissionCount`,
      "the number of granted permission rows",
    );
  }
}

export function validateDirectBindingListPage(
  value: unknown,
  path: string,
): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "managementNav",
    "heading",
    "summary",
    "bindings",
    "notice",
    "grant",
    "readOnlyReason",
    "pagination",
  ]);
  validateManagementPageHeader(
    page,
    path,
    "direct-binding-list",
    "direct-bindings",
  );
  validateNotice(page.notice, `${path}.notice`);
  const mutationPolicy = validateDirectGrant(
    page.grant,
    `${path}.grant`,
    page.readOnlyReason,
    `${path}.readOnlyReason`,
  );

  const bindingsPath = `${path}.bindings`;
  const bindings = expectArray(
    page.bindings,
    bindingsPath,
    RENDER_REQUEST_LIMITS.bindingCount,
  );
  const seenIds = new Set<string>();
  let pageAuthority = mutationPolicy.authority;
  bindings.forEach((binding, index) => {
    const bindingPath = `${bindingsPath}[${index}]`;
    const validated = validateBinding(
      binding,
      bindingPath,
      mutationPolicy.authorized,
      pageAuthority,
    );
    pageAuthority ??= validated.authority;
    expectUnique(seenIds, validated.id, `${bindingPath}.id`);
  });
  validateManagementPagination(
    page.pagination,
    `${path}.pagination`,
    DIRECT_BINDINGS_PATH,
    "binding",
  );
}

interface MutationRevision {
  readonly authorization: string;
  readonly target: string;
  readonly csrfToken: string;
}

interface MutationAuthority {
  readonly authorization: string;
  readonly csrfToken: string;
}

interface DirectMutationPolicy {
  readonly authorized: boolean;
  readonly authority: MutationAuthority | null;
}

function validateNotice(value: unknown, path: string): void {
  if (value !== null) {
    expectOneOf(value, path, ["saved", "conflict", "forbidden"]);
  }
}

function validateMutationEnvelope(
  mutation: JsonRecord,
  path: string,
  expectedAction: string,
): { readonly authorization: string; readonly csrfToken: string } {
  const action = expectRouteField(mutation, "action", path);
  if (action !== expectedAction) {
    invalid(`${path}.action`, `the exact ${expectedAction} mutation path`);
  }
  const csrfToken = expectGeneratedCsrfToken(
    mutation.csrfToken,
    `${path}.csrfToken`,
  );
  const authorization = expectPositiveRevision(
    mutation.expectedAuthorizationRevision,
    `${path}.expectedAuthorizationRevision`,
  );
  return { authorization, csrfToken };
}

function validateMemberStatusUpdate(
  value: unknown,
  path: string,
  principalId: string,
  status: "active" | "disabled",
): void {
  if (value === null) {
    return;
  }
  const update = expectObject(value, path, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "expectedRevision",
    "operation",
  ]);
  validateMutationEnvelope(update, path, `${USERS_PATH}/${principalId}/status`);
  expectAdvanceableRevision(update.expectedRevision, `${path}.expectedRevision`);
  expectLiteral(
    update.operation,
    `${path}.operation`,
    status === "active" ? "disable" : "enable",
  );
}

function validateRoleMutations(
  page: JsonRecord,
  path: string,
  roleId: string,
  immutable: boolean,
): MutationRevision | null {
  if (immutable) {
    if (page.update !== null) {
      invalid(`${path}.update`, "null for an immutable role");
    }
    if (page.delete !== null) {
      invalid(`${path}.delete`, "null for an immutable role");
    }
    return null;
  }

  if (page.delete === null) {
    if (page.update !== null) {
      invalid(`${path}.delete`, "the matching role-delete capability");
    }
    return null;
  }

  const deletePath = `${path}.delete`;
  const deletion = expectObject(page.delete, deletePath, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "expectedRevision",
  ]);
  const deleteEnvelope = validateMutationEnvelope(
    deletion,
    deletePath,
    `${ROLES_PATH}/${roleId}/delete`,
  );
  const deleteRevision = expectPositiveRevision(
    deletion.expectedRevision,
    `${deletePath}.expectedRevision`,
  );

  if (page.update === null) {
    if (deleteRevision !== MAX_I64) {
      invalid(
        `${path}.update`,
        "the matching role-update capability before revision exhaustion",
      );
    }
    return null;
  }

  const updatePath = `${path}.update`;
  const update = expectObject(page.update, updatePath, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "expectedRevision",
  ]);
  const updateEnvelope = validateMutationEnvelope(
    update,
    updatePath,
    `${ROLES_PATH}/${roleId}`,
  );
  const updateRevision = expectAdvanceableRevision(
    update.expectedRevision,
    `${updatePath}.expectedRevision`,
  );
  if (
    updateEnvelope.authorization !== deleteEnvelope.authorization ||
    updateEnvelope.csrfToken !== deleteEnvelope.csrfToken ||
    updateRevision !== deleteRevision
  ) {
    invalid(deletePath, "the update form's exact capability and role revision");
  }
  return {
    authorization: updateEnvelope.authorization,
    target: updateRevision,
    csrfToken: updateEnvelope.csrfToken,
  };
}

function validatePermissionUpdate(
  value: unknown,
  path: string,
  roleId: string,
  permission: string,
  granted: boolean,
  roleMutation: MutationRevision | null,
): void {
  if (value === null) {
    if (roleMutation !== null) {
      invalid(path, "a mutation for every permission of a mutable managed role");
    }
    return;
  }
  if (roleMutation === null) {
    invalid(path, "null without role-management capability");
  }
  const update = expectObject(value, path, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "expectedRevision",
    "operation",
  ]);
  const envelope = validateMutationEnvelope(
    update,
    path,
    `${ROLES_PATH}/${roleId}/permissions/${permission}`,
  );
  const target = expectAdvanceableRevision(
    update.expectedRevision,
    `${path}.expectedRevision`,
  );
  if (
    envelope.authorization !== roleMutation.authorization ||
    envelope.csrfToken !== roleMutation.csrfToken ||
    target !== roleMutation.target
  ) {
    invalid(path, "the role form's exact capability and role revision");
  }
  expectLiteral(
    update.operation,
    `${path}.operation`,
    granted ? "remove" : "add",
  );
}

function validateDirectGrant(
  value: unknown,
  path: string,
  readOnlyReason: unknown,
  reasonPath: string,
): DirectMutationPolicy {
  if (value === null) {
    const reason = expectOneOf(readOnlyReason, reasonPath, [
      "management-unavailable",
      "not-authorized",
      "options-unavailable",
      "options-overflow",
      "no-options",
    ]);
    return {
      authorized:
        reason !== "management-unavailable" && reason !== "not-authorized",
      authority: null,
    };
  }
  if (readOnlyReason !== null) {
    invalid(reasonPath, "null when the complete grant form is available");
  }
  const grant = expectObject(value, path, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "principals",
    "roles",
    "scopes",
  ]);
  const envelope = validateMutationEnvelope(grant, path, DIRECT_BINDINGS_PATH);
  validateSelectOptions(grant.principals, `${path}.principals`, 500, "uuid");
  validateSelectOptions(grant.roles, `${path}.roles`, 500, "uuid");
  validateSelectOptions(grant.scopes, `${path}.scopes`, 1_001, "scope");
  return { authorized: true, authority: envelope };
}

function validateSelectOptions(
  value: unknown,
  path: string,
  maximum: number,
  kind: "uuid" | "scope",
): void {
  const options = expectArray(value, path, maximum);
  if (options.length === 0) {
    invalid(path, "at least one complete selectable option");
  }
  const seen = new Set<string>();
  options.forEach((value, index) => {
    const optionPath = `${path}[${index}]`;
    const option = expectObject(value, optionPath, ["value", "label"]);
    const optionValue = expectString(option.value, `${optionPath}.value`, 64, 1);
    if (kind === "uuid") {
      expectCanonicalUuid(optionValue, `${optionPath}.value`);
    } else if (optionValue !== "tenant") {
      const resource = optionValue.startsWith("repository:")
        ? optionValue.slice("repository:".length)
        : optionValue.startsWith("runner-group:")
          ? optionValue.slice("runner-group:".length)
          : null;
      if (resource === null) {
        invalid(`${optionPath}.value`, "a canonical tenant or resource scope");
      }
      expectCanonicalUuid(resource, `${optionPath}.value`);
    }
    expectUnique(seen, optionValue, `${optionPath}.value`);
    expectDisplayText(option.label, `${optionPath}.label`, 255);
  });
}

function validateBindingRevoke(
  value: unknown,
  path: string,
  bindingId: string,
  source: "direct" | "provider-observed",
  status: "active" | "revoked",
  revision: string,
  mutationAuthorized: boolean,
  pageAuthority: MutationAuthority | null,
): MutationAuthority | null {
  const eligible = source === "direct" && status === "active";
  const revisionCanAdvance = revision !== MAX_I64;
  if (value === null) {
    if (mutationAuthorized && eligible && revisionCanAdvance) {
      invalid(path, "a revoke form for every active direct binding");
    }
    return null;
  }
  if (!mutationAuthorized) {
    invalid(path, "null without direct-binding management authority");
  }
  if (!eligible) {
    invalid(path, "null for provider-observed or non-active bindings");
  }
  if (!revisionCanAdvance) {
    invalid(path, "null after the binding revision is exhausted");
  }
  const revoke = expectObject(value, path, [
    "action",
    "csrfToken",
    "expectedAuthorizationRevision",
    "expectedRevision",
  ]);
  const envelope = validateMutationEnvelope(
    revoke,
    path,
    `${DIRECT_BINDINGS_PATH}/${bindingId}/revoke`,
  );
  const expectedRevision = expectAdvanceableRevision(
    revoke.expectedRevision,
    `${path}.expectedRevision`,
  );
  if (expectedRevision !== revision) {
    invalid(`${path}.expectedRevision`, "the binding's exact revision");
  }
  if (
    pageAuthority !== null &&
    (envelope.authorization !== pageAuthority.authorization ||
      envelope.csrfToken !== pageAuthority.csrfToken)
  ) {
    invalid(path, "the page's exact direct-binding mutation authority");
  }
  return envelope;
}

function expectPositiveRevision(value: unknown, path: string): string {
  const revision = expectString(value, path, 19, 1);
  if (
    !POSITIVE_REVISION.test(revision) ||
    (revision.length === MAX_I64.length && revision > MAX_I64)
  ) {
    invalid(path, "a canonical positive PostgreSQL BIGINT revision");
  }
  return revision;
}

function expectAdvanceableRevision(value: unknown, path: string): string {
  const revision = expectPositiveRevision(value, path);
  if (revision === MAX_I64) {
    invalid(path, "a PostgreSQL BIGINT revision that this mutation can advance");
  }
  return revision;
}

function validateManagementPageHeader(
  page: JsonRecord,
  path: string,
  kind: string,
  area: ManagementArea,
): void {
  expectLiteral(page.kind, `${path}.kind`, kind);
  const shell = validateShell(page.shell, `${path}.shell`);
  if (!shell.authenticated) {
    invalid(`${path}.shell.viewer`, "an authenticated management viewer");
  }
  const [repositoriesNavigation, runnersNavigation, accessNavigation] = shell.navigation;
  if (
    shell.navigation.length !== 3 ||
    shell.homeHref !== "/repositories" ||
    repositoriesNavigation?.label !== "Repositories" ||
    repositoriesNavigation?.href !== "/repositories" ||
    repositoriesNavigation?.current !== false ||
    runnersNavigation?.label !== "Runners" ||
    runnersNavigation?.href !== "/runners" ||
    runnersNavigation?.current !== false ||
    accessNavigation?.label !== "Access" ||
    accessNavigation?.href !== USERS_PATH ||
    accessNavigation?.current !== true
  ) {
    invalid(
      `${path}.shell.navigation`,
      "coherent Repositories and current Access product navigation",
    );
  }
  validateManagementNavigation(
    page.managementNav,
    `${path}.managementNav`,
    area,
  );
  expectTextField(page, "heading", path);
  expectTextField(
    page,
    "summary",
    path,
    RENDER_REQUEST_LIMITS.longTextLength,
  );
}

function validateManagementNavigation(
  value: unknown,
  path: string,
  area: ManagementArea,
): void {
  const navigation = expectObject(value, path, [
    "usersHref",
    "rolesHref",
    "directBindingsHref",
    "current",
  ]);
  const destinations = [
    ["usersHref", USERS_PATH],
    ["rolesHref", ROLES_PATH],
    ["directBindingsHref", DIRECT_BINDINGS_PATH],
  ] as const;
  for (const [key, expected] of destinations) {
    const href = expectRouteField(navigation, key, path);
    if (href !== expected) {
      invalid(`${path}.${key}`, `the canonical ${expected} destination`);
    }
  }
  expectLiteral(navigation.current, `${path}.current`, area);
}

function validateManagementPagination(
  value: unknown,
  path: string,
  listPath: string,
  cursorKind: "uuid" | "binding",
): void {
  const pagination = expectObject(value, path, [
    "previousHref",
    "nextHref",
    "label",
  ]);
  if (pagination.previousHref !== null) {
    invalid(`${path}.previousHref`, "null for the current forward-only list");
  }
  const nextHref = expectNullableRoute(
    pagination.nextHref,
    `${path}.nextHref`,
  );
  if (nextHref !== null) {
    const prefix = `${listPath}?cursor=`;
    if (!nextHref.startsWith(prefix)) {
      invalid(`${path}.nextHref`, "the next page of this management list");
    }
    const cursor = nextHref.slice(prefix.length);
    if (cursorKind === "uuid") {
      expectCanonicalUuid(cursor, `${path}.nextHref`);
    } else if (cursor.startsWith("d%3A")) {
      expectCanonicalUuid(cursor.slice(4), `${path}.nextHref`);
    } else if (cursor.startsWith("g%3A")) {
      const parts = cursor.slice(4).split("%3A");
      if (parts.length !== 2) {
        invalid(`${path}.nextHref`, "a canonical provider-binding cursor");
      }
      expectCanonicalUuid(parts[0], `${path}.nextHref`);
      expectCanonicalUuid(parts[1], `${path}.nextHref`);
    } else {
      invalid(`${path}.nextHref`, "a canonical direct or provider-binding cursor");
    }
  }
  expectTextField(pagination, "label", path);
}

function validateManagedUser(
  value: unknown,
  path: string,
): {
  readonly id: string;
  readonly href: string;
  readonly providerLogin: string;
  readonly displayName: string | null;
  readonly status: "active" | "disabled";
} {
  const user = expectObject(value, path, [
    "id",
    "href",
    "providerId",
    "providerLogin",
    "displayName",
    "status",
  ]);
  const id = expectCanonicalUuid(user.id, `${path}.id`);
  const href = expectRouteField(user, "href", path);
  if (href !== `${USERS_PATH}/${id}`) {
    invalid(`${path}.href`, "the exact user-detail destination");
  }
  expectDisplayText(user.providerId, `${path}.providerId`, 128);
  const providerLogin = expectDisplayText(
    user.providerLogin,
    `${path}.providerLogin`,
    255,
  );
  let displayName: string | null = null;
  if (user.displayName !== null) {
    displayName = expectDisplayText(user.displayName, `${path}.displayName`, 255);
  }
  const status = expectOneOf(user.status, `${path}.status`, ["active", "disabled"]);
  return { id, href, providerLogin, displayName, status };
}

function validateRoleSummary(
  value: unknown,
  path: string,
): {
  readonly id: string;
  readonly href: string;
  readonly name: string;
  readonly displayName: string;
  readonly permissionCount: number;
  readonly immutable: boolean;
} {
  const role = expectObject(value, path, [
    "id",
    "href",
    "name",
    "displayName",
    "kind",
    "immutable",
    "permissionCount",
  ]);
  const id = expectCanonicalUuid(role.id, `${path}.id`);
  const href = expectRouteField(role, "href", path);
  if (href !== `${ROLES_PATH}/${id}`) {
    invalid(`${path}.href`, "the exact role-detail destination");
  }
  const name = expectPolicyName(role.name, `${path}.name`);
  const displayName = expectDisplayText(
    role.displayName,
    `${path}.displayName`,
    255,
  );
  const kind = expectOneOf(role.kind, `${path}.kind`, ["built-in", "custom"]);
  expectBoolean(role.immutable, `${path}.immutable`);
  if ((kind === "built-in") !== (role.immutable === true)) {
    invalid(
      `${path}.immutable`,
      kind === "built-in"
        ? "true for a built-in role"
        : "false for a custom role",
    );
  }
  const permissionCount = expectInteger(
    role.permissionCount,
    `${path}.permissionCount`,
    0,
    RENDER_REQUEST_LIMITS.permissionCount,
  );
  return {
    id,
    href,
    name,
    displayName,
    permissionCount,
    immutable: role.immutable as boolean,
  };
}

function validateBinding(
  value: unknown,
  path: string,
  mutationAuthorized: boolean,
  pageAuthority: MutationAuthority | null,
): { readonly id: string; readonly authority: MutationAuthority | null } {
  const binding = expectObject(value, path, [
    "id",
    "revision",
    "principal",
    "role",
    "scope",
    "source",
    "status",
    "validUntil",
    "revoke",
  ]);
  const id = expectCanonicalUuid(binding.id, `${path}.id`);
  const revision = expectPositiveRevision(binding.revision, `${path}.revision`);
  validateBindingPrincipal(binding.principal, `${path}.principal`);
  validateBindingRole(binding.role, `${path}.role`);
  validateScope(binding.scope, `${path}.scope`);
  const source = expectOneOf(binding.source, `${path}.source`, [
    "direct",
    "provider-observed",
  ]);
  const status = expectOneOf(binding.status, `${path}.status`, ["active", "revoked"]);
  validateNullableTimestamp(binding.validUntil, `${path}.validUntil`);
  const authority = validateBindingRevoke(
    binding.revoke,
    `${path}.revoke`,
    id,
    source,
    status,
    revision,
    mutationAuthorized,
    pageAuthority,
  );
  return { id, authority };
}

function validateBindingPrincipal(value: unknown, path: string): void {
  const principal = expectObject(value, path, ["id", "href", "label"]);
  const id = expectCanonicalUuid(principal.id, `${path}.id`);
  const href = expectRouteField(principal, "href", path);
  if (href !== `${USERS_PATH}/${id}`) {
    invalid(`${path}.href`, "the exact user-detail destination");
  }
  expectDisplayText(principal.label, `${path}.label`, 255);
}

function validateBindingRole(value: unknown, path: string): void {
  const role = expectObject(value, path, ["id", "href", "name", "label"]);
  const id = expectCanonicalUuid(role.id, `${path}.id`);
  const href = expectRouteField(role, "href", path);
  if (href !== `${ROLES_PATH}/${id}`) {
    invalid(`${path}.href`, "the exact role-detail destination");
  }
  expectPolicyName(role.name, `${path}.name`);
  expectDisplayText(role.label, `${path}.label`, 255);
}

function validateScope(value: unknown, path: string): void {
  const scope = expectObject(value, path, ["kind", "label"]);
  expectOneOf(scope.kind, `${path}.kind`, [
    "tenant",
    "repository",
    "runner-group",
  ]);
  expectDisplayText(scope.label, `${path}.label`, 255);
}

function validateNullableTimestamp(value: unknown, path: string): void {
  if (value !== null) {
    validateTimestamp(value, path);
  }
}

function expectCanonicalUuid(value: unknown, path: string): string {
  const id = expectString(value, path, 36, 36);
  if (!CANONICAL_UUID.test(id) || id === NIL_UUID) {
    invalid(path, "a canonical lowercase non-nil UUID");
  }
  return id;
}

function expectPolicyName(value: unknown, path: string): string {
  const name = expectString(value, path, 128, 1);
  if (!POLICY_NAME.test(name)) {
    invalid(path, "a portable policy name");
  }
  return name;
}
