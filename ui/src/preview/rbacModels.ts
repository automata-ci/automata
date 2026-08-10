import type {
  DirectBindingListPageModel,
  ManagedUserModel,
  PageModel,
  RbacManagementNavigationModel,
  RbacRoleSummaryModel,
  RoleDetailPageModel,
  RoleListPageModel,
  ShellModel,
  UserDetailPageModel,
  UserListPageModel,
} from "../models";
import { previewShell } from "./sampleData";

export type PreviewRbacView =
  | "users"
  | "user"
  | "roles"
  | "role"
  | "bindings";

export const PREVIEW_RBAC_VIEWS: ReadonlySet<string> = new Set([
  "users",
  "user",
  "roles",
  "role",
  "bindings",
]);

const USERS_HREF = "?view=users";
const ROLES_HREF = "?view=roles";
const BINDINGS_HREF = "?view=bindings";
const ADA_PRINCIPAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GRACE_PRINCIPAL_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const RELEASE_REVIEWER_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const TENANT_VIEWER_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
export const PREVIEW_DIRECT_BINDING_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const PROVIDER_BINDING_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";

const managementNavBase = {
  usersHref: USERS_HREF,
  rolesHref: ROLES_HREF,
  directBindingsHref: BINDINGS_HREF,
} as const;

const adaUser: ManagedUserModel = {
  id: ADA_PRINCIPAL_ID,
  href: "?view=user&user=ada-lovelace",
  providerId: "github",
  providerLogin: "ada-lovelace",
  displayName: "Ada Lovelace",
  status: "active",
};

const graceUser: ManagedUserModel = {
  id: GRACE_PRINCIPAL_ID,
  href: "?view=user&user=grace-hopper",
  providerId: "github",
  providerLogin: "grace-hopper",
  displayName: "Grace Hopper",
  status: "disabled",
};

const users: readonly ManagedUserModel[] = [adaUser, graceUser];

const tenantViewerRole: RbacRoleSummaryModel = {
  id: TENANT_VIEWER_ID,
  href: "?view=role&role=tenant-viewer",
  name: "tenant-viewer",
  displayName: "Tenant viewer",
  kind: "built-in",
  immutable: true,
  permissionCount: 2,
};

const releaseReviewerRole: RbacRoleSummaryModel = {
  id: RELEASE_REVIEWER_ID,
  href: "?view=role&role=release-reviewer",
  name: "release-reviewer",
  displayName: "Release reviewer",
  kind: "custom",
  immutable: false,
  permissionCount: 2,
};

const roles: readonly RbacRoleSummaryModel[] = [
  tenantViewerRole,
  releaseReviewerRole,
];

export function previewRbacPage(
  view: PreviewRbacView,
  searchParameters: URLSearchParams,
): PageModel | null {
  switch (view) {
    case "users":
      return hasExactKeys(searchParameters, ["view"])
        ? previewUserList()
        : null;
    case "user":
      return hasExactKeys(searchParameters, ["view", "user"])
        ? previewUserDetail(searchParameters.get("user"))
        : null;
    case "roles":
      return hasExactKeys(searchParameters, ["view"])
        ? previewRoleList()
        : null;
    case "role":
      return hasExactKeys(searchParameters, ["view", "role"])
        ? previewRoleDetail(searchParameters.get("role"))
        : null;
    case "bindings":
      return hasExactKeys(searchParameters, ["view"])
        ? previewDirectBindings()
        : null;
  }
}

export function previewUserList(): UserListPageModel {
  return {
    kind: "user-list",
    shell: rbacShell("Users · Access management · Automata"),
    managementNav: managementNav("users"),
    heading: "Users",
    summary: "Authenticated tenant members and their current access status.",
    users,
    notice: null,
    pagination: { previousHref: null, nextHref: null, label: "2 users" },
  };
}

export function previewUserDetail(
  requestedUser: string | null = "ada-lovelace",
): UserDetailPageModel | null {
  const user = requestedUser === "ada-lovelace"
    ? adaUser
    : requestedUser === "grace-hopper"
      ? graceUser
      : undefined;
  if (user === undefined) {
    return null;
  }
  const isAda = user.id === ADA_PRINCIPAL_ID;
  const heading = user.displayName ?? `@${user.providerLogin}`;
  return {
    kind: "user-detail",
    shell: rbacShell(`${heading} · Access management · Automata`),
    managementNav: managementNav("users"),
    heading,
    summary: "Provider identity and visible role assignments for this tenant member.",
    user,
    notice: null,
    statusUpdate: null,
    roleAssignments: [
      {
        bindingId: isAda ? PREVIEW_DIRECT_BINDING_ID : PROVIDER_BINDING_ID,
        bindingHref: BINDINGS_HREF,
        roleHref: isAda
          ? "?view=role&role=release-reviewer"
          : "?view=role&role=tenant-viewer",
        roleId: isAda ? RELEASE_REVIEWER_ID : TENANT_VIEWER_ID,
        roleName: isAda ? "release-reviewer" : "tenant-viewer",
        roleDisplayName: isAda ? "Release reviewer" : "Tenant viewer",
        scope: isAda
          ? { kind: "repository", label: "automata-ci/automata" }
          : { kind: "tenant", label: "Production" },
        source: isAda ? "direct" : "provider-observed",
        status: "active",
        validUntil: isAda
          ? {
              iso: "2026-09-01T00:00:00Z",
              label: "1 Sep 2026, 00:00 UTC",
            }
          : null,
      },
    ],
  };
}

export function previewRoleList(): RoleListPageModel {
  return {
    kind: "role-list",
    shell: rbacShell("Roles · Access management · Automata"),
    managementNav: managementNav("roles"),
    heading: "Roles",
    summary: "Built-in and custom roles with their explicit permission grants.",
    roles,
    notice: null,
    create: null,
    pagination: { previousHref: null, nextHref: null, label: "2 roles" },
  };
}

export function previewRoleDetail(
  requestedRole: string | null = "release-reviewer",
): RoleDetailPageModel | null {
  const role = requestedRole === "tenant-viewer"
    ? tenantViewerRole
    : requestedRole === "release-reviewer"
      ? releaseReviewerRole
      : undefined;
  if (role === undefined) {
    return null;
  }
  const isBuiltIn = role.kind === "built-in";
  return {
    kind: "role-detail",
    shell: rbacShell(`${role.displayName} · Access management · Automata`),
    managementNav: managementNav("roles"),
    heading: role.displayName,
    summary: "Role identity and explicit permission grants.",
    role,
    notice: null,
    update: null,
    delete: null,
    permissions: [
      {
        name: "runs:read",
        description: "Read authorized workflow-run metadata.",
        granted: true,
        update: null,
      },
      {
        name: isBuiltIn ? "logs:read" : "artifacts:download",
        description: isBuiltIn
          ? "Read authorized workflow job logs."
          : "Download authorized finalized artifacts.",
        granted: true,
        update: null,
      },
      {
        name: "repositories:settings:update",
        description: "Change authorized repository settings.",
        granted: false,
        update: null,
      },
    ],
  };
}

export function previewDirectBindings(): DirectBindingListPageModel {
  return {
    kind: "direct-binding-list",
    shell: rbacShell("Direct bindings · Access management · Automata"),
    managementNav: managementNav("direct-bindings"),
    heading: "Direct bindings",
    summary: "Direct and provider-observed role assignments with their exact scopes.",
    notice: null,
    grant: null,
    readOnlyReason: "not-authorized",
    bindings: [
      {
        id: PREVIEW_DIRECT_BINDING_ID,
        revision: "4",
        principal: {
          id: ADA_PRINCIPAL_ID,
          href: adaUser.href,
          label: adaUser.displayName ?? adaUser.providerLogin,
        },
        role: {
          id: RELEASE_REVIEWER_ID,
          href: releaseReviewerRole.href,
          name: releaseReviewerRole.name,
          label: releaseReviewerRole.displayName,
        },
        scope: { kind: "repository", label: "automata-ci/automata" },
        source: "direct",
        status: "active",
        validUntil: {
          iso: "2026-09-01T00:00:00Z",
          label: "1 Sep 2026, 00:00 UTC",
        },
        revoke: null,
      },
      {
        id: PROVIDER_BINDING_ID,
        revision: "8",
        principal: {
          id: GRACE_PRINCIPAL_ID,
          href: graceUser.href,
          label: graceUser.displayName ?? graceUser.providerLogin,
        },
        role: {
          id: TENANT_VIEWER_ID,
          href: tenantViewerRole.href,
          name: tenantViewerRole.name,
          label: tenantViewerRole.displayName,
        },
        scope: { kind: "tenant", label: "Production" },
        source: "provider-observed",
        status: "active",
        validUntil: null,
        revoke: null,
      },
    ],
    pagination: { previousHref: null, nextHref: null, label: "2 bindings" },
  };
}

function rbacShell(documentTitle: string): ShellModel {
  return {
    ...previewShell,
    homeHref: "?view=repositories",
    documentTitle,
    description: "Review tenant users, roles, permissions, and role bindings.",
    navigation: [
      { label: "Repositories", href: "?view=repositories" },
      { label: "Access", href: USERS_HREF, current: true },
    ],
  };
}

function managementNav(
  current: RbacManagementNavigationModel["current"],
): RbacManagementNavigationModel {
  return { ...managementNavBase, current };
}

function hasExactKeys(
  searchParameters: URLSearchParams,
  exactKeys: readonly string[],
): boolean {
  const entries = [...searchParameters.keys()];
  return (
    entries.length === exactKeys.length &&
    new Set(entries).size === entries.length &&
    exactKeys.every((key) => entries.includes(key))
  );
}
