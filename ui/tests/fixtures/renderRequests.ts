import type { RenderRequest, ShellModel } from "../../src/models";

export const PRIMARY_RUN_ID = "550e8400-e29b-41d4-a716-446655440000";
export const SECONDARY_RUN_ID = "550e8400-e29b-41d4-a716-446655440001";
const CI_WORKFLOW_ID = "11111111-1111-4111-8111-11111111111a";
const RELEASE_WORKFLOW_ID = "11111111-1111-4111-8111-11111111111b";
export const PRIMARY_JOB_ID = "33333333-3333-4333-8333-33333333333c";
const SECONDARY_JOB_ID = "44444444-4444-4444-8444-44444444444d";
const SOURCE_REPOSITORY_HREF = "https://github.com/automata-ci/automata";
const PRIMARY_COMMIT = "26713a895eb6744012da74726e59230a259357c4";
const SECONDARY_COMMIT = "3278d9e87d30ca91c5ec19bcef01cec33aa4182e";
export const SHELL_CSRF_TOKEN = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

const shell: ShellModel = {
  productName: "Automata",
  homeHref: "/repositories",
  signIn: null,
  signOut: {
    action: "/auth/logout",
    csrfToken: SHELL_CSRF_TOKEN,
  },
  documentTitle: "Workflow runs · Automata",
  description: "Browse repositories and review workflow runs, jobs, logs, and artifacts.",
  viewer: { displayName: "Ada" },
  navigation: [
    {
      label: "Repositories",
      href: "/repositories",
      current: false,
    },
    {
      label: "Actions",
      href: "/automata-ci/automata/actions",
      current: true,
    },
  ],
};

const repository = {
  owner: "automata-ci",
  name: "automata",
  sourceHref: SOURCE_REPOSITORY_HREF,
  runsHref: "/automata-ci/automata/actions",
  settingsHref: null,
} as const;

const common = {
  schemaVersion: 1,
  host: {
    locale: "en",
    cspNonce: "nonce-value",
    assets: {
      clientEntry: "/assets/entry-client-abc123.js",
      stylesheets: ["/assets/entry-client-abc123.css"],
    },
  },
} as const;

export const repositoryDirectoryRequest: RenderRequest = {
  ...common,
  page: {
    kind: "repository-directory",
    shell: {
      ...shell,
      signIn: {
        action: "/auth/github/login",
        returnPath: "/repositories",
      },
      signOut: null,
      documentTitle: "Repositories · Automata",
      viewer: null,
      navigation: [{ label: "Repositories", href: "/repositories", current: true }],
    },
    heading: "Repositories",
    summary: "Browse repositories available under your current access.",
    repositories: [
      {
        owner: "automata-ci",
        name: "automata",
        sourceHref: SOURCE_REPOSITORY_HREF,
        actionsHref: "/automata-ci/automata/actions",
        settingsHref: null,
      },
    ],
    pagination: {
      nextHref: "/repositories?cursor=AQFwcmV2aWV3X25leHQ",
      label: "1 repository on this page",
    },
  },
};

export const repositorySecretsDirectoryRequest: RenderRequest = {
  ...common,
  page: {
    kind: "repository-directory",
    shell: {
      ...shell,
      documentTitle: "Repositories · Automata",
      navigation: [{ label: "Repositories", href: "/repositories", current: true }],
    },
    heading: "Repositories",
    summary: "Browse repositories available under your current access.",
    repositories: [
      {
        owner: "automata-ci",
        name: "automata",
        sourceHref: SOURCE_REPOSITORY_HREF,
        actionsHref: null,
        settingsHref: "/automata-ci/automata/settings/secrets",
      },
    ],
    pagination: {
      nextHref: null,
      label: "1 repository on this page",
    },
  },
};

export const runListRequest: RenderRequest = {
  ...common,
  page: {
    kind: "run-list",
    shell,
    repository,
    heading: "Workflow runs",
    summary: "Continuous integration runs for automata-ci/automata.",
    filters: {
      action: repository.runsHref,
      status: "all",
      branch: "main",
      clearHref: repository.runsHref,
    },
    workflowNavigation: {
      selectedWorkflow: null,
      workflows: [
        {
          id: CI_WORKFLOW_ID,
          name: "CI",
          href: `/automata-ci/automata/actions/workflows/${CI_WORKFLOW_ID}`,
          enabled: true,
        },
        {
          id: RELEASE_WORKFLOW_ID,
          name: "Release",
          href: `/automata-ci/automata/actions/workflows/${RELEASE_WORKFLOW_ID}`,
          enabled: false,
        },
      ],
      pagination: {
        previousHref: null,
        nextHref: null,
        label: "2 workflows",
      },
    },
    runs: [
      {
        id: PRIMARY_RUN_ID,
        number: "1842",
        name: "Build and test <release candidate>",
        workflowName: "CI",
        workflowHref: `/automata-ci/automata/actions/workflows/${CI_WORKFLOW_ID}`,
        href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}`,
        status: { label: "In progress", tone: "running" },
        sourceRef: {
          name: "main",
          kind: "branch",
          href: `${SOURCE_REPOSITORY_HREF}/tree/main`,
        },
        event: "push",
        actor: "ada<script>alert(1)</script>",
        commit: {
          shortSha: PRIMARY_COMMIT.slice(0, 7),
          message: "Run Automata's own CI",
          href: `${SOURCE_REPOSITORY_HREF}/commit/${PRIMARY_COMMIT}`,
        },
        createdAt: {
          iso: "2026-08-06T08:15:00Z",
          label: "6 Aug 2026, 08:15 UTC",
        },
        durationLabel: null,
      },
      {
        id: SECONDARY_RUN_ID,
        number: "1841",
        name: "Workflow compatibility suite",
        workflowName: "CI",
        workflowHref: `/automata-ci/automata/actions/workflows/${CI_WORKFLOW_ID}`,
        href: `/automata-ci/automata/actions/runs/${SECONDARY_RUN_ID}`,
        status: { label: "Succeeded", tone: "success" },
        sourceRef: null,
        event: "pull_request",
        actor: null,
        commit: {
          shortSha: SECONDARY_COMMIT.slice(0, 7),
          message: null,
          href: `${SOURCE_REPOSITORY_HREF}/commit/${SECONDARY_COMMIT}`,
        },
        createdAt: {
          iso: "2026-08-06T07:44:00Z",
          label: "6 Aug 2026, 07:44 UTC",
        },
        durationLabel: "8m 02s",
      },
    ],
    pagination: {
      previousHref: null,
      nextHref: null,
      label: "2 workflow runs",
    },
  },
};

export const runDetailRequest: RenderRequest = {
  ...common,
  host: { ...common.host, cspNonce: "nonce-value" },
  page: {
    kind: "run-detail",
    shell: {
      ...shell,
      documentTitle: "Build and test release candidate · CI · Automata",
    },
    repository,
    run: {
      number: "1842",
      name: "Build and test release candidate",
      workflowName: "CI",
      workflowHref: `/automata-ci/automata/actions/workflows/${CI_WORKFLOW_ID}`,
      status: { label: "In progress", tone: "running" },
      sourceRef: {
        name: "main",
        kind: "branch",
        href: `${SOURCE_REPOSITORY_HREF}/tree/main`,
      },
      event: "push",
      actor: null,
      commit: {
        shortSha: PRIMARY_COMMIT.slice(0, 7),
        message: null,
        href: `${SOURCE_REPOSITORY_HREF}/commit/${PRIMARY_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-06T08:15:00Z",
        label: "6 Aug 2026, 08:15 UTC",
      },
      durationLabel: null,
      attempt: 1,
    },
    jobs: {
      visibility: "full",
      items: [
        {
          id: PRIMARY_JOB_ID,
          name: "Linux release build",
          href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/${PRIMARY_JOB_ID}`,
          runnerLabel: null,
          status: { label: "In progress", tone: "running" },
          startedAt: {
            iso: "2026-08-06T08:15:05Z",
            label: "6 Aug 2026, 08:15 UTC",
          },
          durationLabel: null,
        },
      ],
    },
    jobPagination: {
      previousHref: null,
      nextHref: null,
      label: "1 job",
    },
    artifacts: {
      visibility: "full",
      items: [
        {
          id: "73",
          name: "automata-x86_64-unknown-linux-musl",
          sizeLabel: "18.4 MB",
          digest:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          downloadHref: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/artifacts/73`,
          expiresAt: null,
        },
      ],
    },
    rerun: null,
  },
};

export const jobLogRequest: RenderRequest = {
  ...common,
  host: { ...common.host, cspNonce: "nonce-value" },
  page: {
    kind: "job-log",
    shell: {
      ...shell,
      documentTitle: "Linux release build logs · Automata",
    },
    repository,
    run: {
      number: "1842",
      name: "Build and test release candidate",
      href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}`,
      workflowName: "CI",
      workflowHref: `/automata-ci/automata/actions/workflows/${CI_WORKFLOW_ID}`,
      attempt: 1,
    },
    jobs: [
      {
        id: PRIMARY_JOB_ID,
        name: "Linux release build",
        href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/${PRIMARY_JOB_ID}`,
        status: { label: "In progress", tone: "running" },
      },
      {
        id: SECONDARY_JOB_ID,
        name: "Workspace tests",
        href: null,
        status: { label: "Succeeded", tone: "success" },
      },
    ],
    navigationPagination: {
      previousHref: null,
      nextHref: null,
      label: "2 jobs",
    },
    job: {
      id: PRIMARY_JOB_ID,
      name: "Linux release build",
      href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/${PRIMARY_JOB_ID}`,
      attempt: 2,
      runnerLabel: null,
      status: { label: "In progress", tone: "running" },
      startedAt: {
        iso: "2026-08-06T08:15:05Z",
        label: "6 Aug 2026, 08:15 UTC",
      },
      durationLabel: null,
    },
    logVisibility: "full",
    live: {
      ticketHref: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/${PRIMARY_JOB_ID}/live-ticket`,
      state: "open",
    },
    notice:
      "This job is still running. This page updates automatically as logs are committed.",
  },
};

export const deepLinkSignInRequest: RenderRequest = {
  ...common,
  page: {
    kind: "deep-link-sign-in",
    shell: {
      ...shell,
      signIn: {
        action: "/auth/github/login",
        returnPath: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/${PRIMARY_JOB_ID}`,
      },
      signOut: null,
      documentTitle: "Sign in to view this run · Automata",
      viewer: null,
      navigation: [
        { label: "Repositories", href: "/repositories", current: true },
      ],
    },
  },
};

export const repositorySettingsRequest: RenderRequest = {
  ...common,
  host: { ...common.host, cspNonce: "nonce-value" },
  page: {
    kind: "repository-settings",
    shell: {
      ...shell,
      documentTitle: "Repository access settings · Automata",
      description:
        "Review access defaults for new workflow runs and their output.",
    },
    repository: {
      ...repository,
      settingsHref: "/automata-ci/automata/settings/access",
    },
    heading: "Repository access",
    summary:
      "Choose who can view new workflow runs and their output in automata-ci/automata.",
    settingsNavigation: {
      accessHref: "/automata-ci/automata/settings/access",
      secretsHref: "/automata-ci/automata/settings/secrets",
      current: "access",
    },
    revision: "7",
    policy: {
      dashboard: "public",
      logs: "authenticated",
      artifacts: "private",
    },
    update: {
      action: "/automata-ci/automata/settings/access",
      csrfToken: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    },
  },
};

export const REPOSITORY_SECRET_ID = "77777777-7777-4777-8777-777777777777";
export const REPOSITORY_SECRET_CREATE_ID = "88888888-8888-4888-8888-888888888888";
const REPOSITORY_SECRET_CREATE_MUTATION_ID =
  "99999999-9999-4999-8999-999999999999";
const REPOSITORY_SECRET_REPLACE_MUTATION_ID =
  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";

export const repositorySecretsRequest: RenderRequest = {
  ...common,
  page: {
    kind: "repository-secrets",
    shell: {
      ...shell,
      documentTitle: "Repository secrets · Automata",
      description: "Create and rotate encrypted repository secrets.",
    },
    repository: {
      ...repository,
      settingsHref: "/automata-ci/automata/settings/access",
    },
    heading: "Repository secrets",
    summary:
      "Review encrypted secret metadata stored for automata-ci/automata.",
    settingsNavigation: {
      accessHref: "/automata-ci/automata/settings/access",
      secretsHref: "/automata-ci/automata/settings/secrets",
      current: "secrets",
    },
    notice: null,
    maximumValueBytes: 65_536,
    provider: {
      id: "builtin",
      state: "active",
      health: "healthy",
      activation: null,
    },
    create: {
      action: "/automata-ci/automata/settings/secrets",
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "12",
      secretId: REPOSITORY_SECRET_CREATE_ID,
      mutationId: REPOSITORY_SECRET_CREATE_MUTATION_ID,
    },
    secrets: [
      {
        id: REPOSITORY_SECRET_ID,
        name: "DEPLOY_TOKEN",
        providerId: "builtin",
        state: "active",
        currentVersion: "2",
        revision: "5",
        updatedAt: {
          iso: "2026-08-09T12:30:00Z",
          label: "9 Aug 2026, 12:30 UTC",
        },
        replace: {
          action: `/automata-ci/automata/settings/secrets/${REPOSITORY_SECRET_ID}/replace`,
          csrfToken: SHELL_CSRF_TOKEN,
          expectedAuthorizationRevision: "12",
          mutationId: REPOSITORY_SECRET_REPLACE_MUTATION_ID,
        },
        delete: {
          action: `/automata-ci/automata/settings/secrets/${REPOSITORY_SECRET_ID}/delete`,
          csrfToken: SHELL_CSRF_TOKEN,
          expectedAuthorizationRevision: "12",
        },
      },
    ],
    pagination: {
      firstHref: null,
      nextHref: null,
      label: "1 secret",
    },
  },
};

export const RBAC_USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const RBAC_SECOND_USER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const RBAC_ROLE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const RBAC_BUILT_IN_ROLE_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
export const RBAC_BINDING_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const RBAC_PROVIDER_BINDING_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";

const rbacShell: ShellModel = {
  ...shell,
  documentTitle: "Access management · Automata",
  description: "Review tenant users, roles, permissions, and role bindings.",
  navigation: [
    {
      label: "Repositories",
      href: "/repositories",
    },
    {
      label: "Access",
      href: "/settings/access/users",
      current: true,
    },
  ],
};

const managementNav = {
  usersHref: "/settings/access/users",
  rolesHref: "/settings/access/roles",
  directBindingsHref: "/settings/access/direct-bindings",
} as const;

const primaryManagedUser = {
  id: RBAC_USER_ID,
  href: `/settings/access/users/${RBAC_USER_ID}`,
  providerId: "github",
  providerLogin: "ada-lovelace",
  displayName: "Ada Lovelace",
  status: "active",
} as const;

const secondaryManagedUser = {
  id: RBAC_SECOND_USER_ID,
  href: `/settings/access/users/${RBAC_SECOND_USER_ID}`,
  providerId: "github",
  providerLogin: "grace-hopper",
  displayName: null,
  status: "disabled",
} as const;

const customRole = {
  id: RBAC_ROLE_ID,
  href: `/settings/access/roles/${RBAC_ROLE_ID}`,
  name: "release-reviewer",
  displayName: "Release reviewer",
  kind: "custom",
  immutable: false,
  permissionCount: 1,
} as const;

const builtInRole = {
  id: RBAC_BUILT_IN_ROLE_ID,
  href: `/settings/access/roles/${RBAC_BUILT_IN_ROLE_ID}`,
  name: "tenant-viewer",
  displayName: "Tenant viewer",
  kind: "built-in",
  immutable: true,
  permissionCount: 2,
} as const;

const repositoryScope = {
  kind: "repository",
  label: "automata-ci/automata",
} as const;

export const userListRequest: RenderRequest = {
  ...common,
  page: {
    kind: "user-list",
    shell: {
      ...rbacShell,
      documentTitle: "Users · Access management · Automata",
    },
    managementNav: { ...managementNav, current: "users" },
    heading: "Users",
    summary: "Review authenticated tenant members and their current status.",
    users: [primaryManagedUser, secondaryManagedUser],
    notice: null,
    pagination: { previousHref: null, nextHref: null, label: "2 users" },
  },
};

export const userDetailRequest: RenderRequest = {
  ...common,
  page: {
    kind: "user-detail",
    shell: {
      ...rbacShell,
      documentTitle: "Ada Lovelace · Access management · Automata",
    },
    managementNav: { ...managementNav, current: "users" },
    heading: "Ada Lovelace",
    summary:
      "Stable provider identity, current status, and visible role assignments.",
    user: primaryManagedUser,
    notice: null,
    statusUpdate: null,
    roleAssignments: [
      {
        bindingId: RBAC_BINDING_ID,
        bindingHref: "/settings/access/direct-bindings",
        roleId: customRole.id,
        roleHref: customRole.href,
        roleName: customRole.name,
        roleDisplayName: customRole.displayName,
        scope: repositoryScope,
        source: "direct",
        status: "active",
        validUntil: {
          iso: "2026-09-01T00:00:00Z",
          label: "1 Sep 2026, 00:00 UTC",
        },
      },
    ],
  },
};

export const roleListRequest: RenderRequest = {
  ...common,
  page: {
    kind: "role-list",
    shell: {
      ...rbacShell,
      documentTitle: "Roles · Access management · Automata",
    },
    managementNav: { ...managementNav, current: "roles" },
    heading: "Roles",
    summary:
      "Review built-in and custom roles and their explicit permission grants.",
    roles: [builtInRole, customRole],
    notice: null,
    create: null,
    pagination: { previousHref: null, nextHref: null, label: "2 roles" },
  },
};

export const roleDetailRequest: RenderRequest = {
  ...common,
  page: {
    kind: "role-detail",
    shell: {
      ...rbacShell,
      documentTitle: "Release reviewer · Access management · Automata",
    },
    managementNav: { ...managementNav, current: "roles" },
    heading: "Release reviewer",
    summary: "Review this role and its explicit permission grants.",
    role: customRole,
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
        name: "artifacts:download",
        description: "Download authorized finalized artifacts.",
        granted: false,
        update: null,
      },
    ],
  },
};

export const directBindingListRequest: RenderRequest = {
  ...common,
  page: {
    kind: "direct-binding-list",
    shell: {
      ...rbacShell,
      documentTitle: "Direct bindings · Access management · Automata",
    },
    managementNav: { ...managementNav, current: "direct-bindings" },
    heading: "Direct bindings",
    summary:
      "Review exact direct and provider-observed role assignments and scopes.",
    notice: null,
    grant: null,
    readOnlyReason: "management-unavailable",
    bindings: [
      {
        id: RBAC_BINDING_ID,
        revision: "4",
        principal: {
          id: primaryManagedUser.id,
          href: primaryManagedUser.href,
          label: primaryManagedUser.displayName,
        },
        role: {
          id: customRole.id,
          href: customRole.href,
          name: customRole.name,
          label: customRole.displayName,
        },
        scope: repositoryScope,
        source: "direct",
        status: "active",
        validUntil: null,
        revoke: null,
      },
      {
        id: RBAC_PROVIDER_BINDING_ID,
        revision: "8",
        principal: {
          id: secondaryManagedUser.id,
          href: secondaryManagedUser.href,
          label: secondaryManagedUser.providerLogin,
        },
        role: {
          id: builtInRole.id,
          href: builtInRole.href,
          name: builtInRole.name,
          label: builtInRole.displayName,
        },
        scope: {
          kind: "tenant",
          label: "Production tenant",
        },
        source: "provider-observed",
        status: "active",
        validUntil: null,
        revoke: null,
      },
    ],
    pagination: { previousHref: null, nextHref: null, label: "2 bindings" },
  },
};
