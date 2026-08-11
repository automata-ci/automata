import type { RunStatusFilter } from "./runFilters";

type StatusTone =
  "neutral" | "queued" | "running" | "success" | "failure" | "warning";

interface TimestampModel {
  readonly iso: string;
  readonly label: string;
}

interface ViewerModel {
  readonly displayName: string;
}

interface NavigationItemModel {
  readonly label: string;
  readonly href: string;
  readonly current?: boolean;
}

interface SignInModel {
  readonly action: string;
  readonly returnPath: string;
}

interface SignOutModel {
  readonly action: string;
  readonly csrfToken: string;
}

export interface ShellModel {
  readonly productName: string;
  readonly homeHref: string;
  readonly signIn: SignInModel | null;
  readonly signOut: SignOutModel | null;
  readonly documentTitle: string;
  readonly description: string;
  readonly viewer: ViewerModel | null;
  readonly navigation: readonly NavigationItemModel[];
}

export interface RepositoryModel {
  readonly owner: string;
  readonly name: string;
  readonly runsHref: string;
  readonly sourceHref: string;
  /** Present only when the host authorizes a discoverable settings view. */
  readonly settingsHref: string | null;
}

interface RepositorySettingsRepositoryModel extends RepositoryModel {
  readonly settingsHref: string;
}

export interface StatusModel {
  readonly label: string;
  readonly tone: StatusTone;
}

export interface CommitModel {
  readonly shortSha: string;
  readonly message: string | null;
  readonly href: string;
}

export type SourceRefKind = "branch" | "tag" | "ref";

export interface SourceRefModel {
  readonly name: string;
  readonly kind: SourceRefKind;
  readonly href: string;
}

export interface RunListItemModel {
  readonly id: string;
  /** Lossless human-facing run number; never use `id` as display text. */
  readonly number: string;
  readonly name: string;
  readonly workflowName: string;
  readonly workflowHref: string;
  readonly href: string;
  readonly status: StatusModel;
  readonly sourceRef: SourceRefModel | null;
  readonly event: string;
  readonly actor: string | null;
  readonly commit: CommitModel;
  readonly createdAt: TimestampModel;
  readonly durationLabel: string | null;
}

export interface RunFiltersModel {
  readonly action: string;
  readonly status: RunStatusFilter;
  readonly branch: string;
  readonly clearHref: string;
}

export interface WorkflowNavigationItemModel {
  readonly id: string;
  readonly name: string;
  readonly href: string;
  readonly enabled: boolean;
}

export interface WorkflowNavigationModel {
  readonly selectedWorkflow: WorkflowNavigationItemModel | null;
  readonly workflows: readonly WorkflowNavigationItemModel[];
  readonly pagination: PaginationModel;
}

export interface PaginationModel {
  readonly previousHref: string | null;
  readonly nextHref: string | null;
  readonly label: string;
}

export interface RepositoryDirectoryItemModel {
  readonly owner: string;
  readonly name: string;
  readonly sourceHref: string;
  readonly actionsHref: string | null;
  readonly settingsHref: string | null;
}

export interface RepositoryDirectoryPageModel {
  readonly kind: "repository-directory";
  readonly shell: ShellModel;
  readonly heading: string;
  readonly summary: string;
  readonly repositories: readonly RepositoryDirectoryItemModel[];
  readonly pagination: {
    readonly nextHref: string | null;
    readonly label: string;
  };
}

export interface SetupPageModel {
  readonly kind: "setup";
  readonly shell: ShellModel;
  readonly form: {
    readonly action: "/setup/auth/github";
    readonly returnPath: "/";
  };
}

export interface RunListPageModel {
  readonly kind: "run-list";
  readonly shell: ShellModel;
  readonly repository: RepositoryModel;
  readonly heading: string;
  readonly summary: string;
  readonly filters: RunFiltersModel;
  readonly workflowNavigation: WorkflowNavigationModel | null;
  readonly runs: readonly RunListItemModel[];
  readonly pagination: PaginationModel;
}

export interface JobModel {
  readonly id: string;
  readonly name: string;
  readonly href: string | null;
  readonly runnerLabel: string | null;
  readonly status: StatusModel;
  readonly startedAt: TimestampModel | null;
  readonly durationLabel: string | null;
}

export interface ArtifactModel {
  readonly id: string;
  readonly name: string;
  readonly sizeLabel: string;
  readonly digest: string;
  readonly downloadHref: string | null;
  readonly expiresAt: TimestampModel | null;
}

export type ResultCollectionVisibility = "full" | "restricted";

export interface ResultCollectionModel<Item> {
  readonly visibility: ResultCollectionVisibility;
  readonly items: readonly Item[];
}

export interface RunDetailModel {
  /** Lossless human-facing run number. */
  readonly number: string;
  readonly name: string;
  readonly workflowName: string;
  readonly workflowHref: string;
  readonly status: StatusModel;
  readonly sourceRef: SourceRefModel | null;
  readonly event: string;
  readonly actor: string | null;
  readonly commit: CommitModel;
  readonly createdAt: TimestampModel;
  readonly durationLabel: string | null;
  readonly attempt: number;
}

export interface RunDetailPageModel {
  readonly kind: "run-detail";
  readonly shell: ShellModel;
  readonly repository: RepositoryModel;
  readonly run: RunDetailModel;
  readonly jobs: ResultCollectionModel<JobModel>;
  readonly jobPagination: PaginationModel;
  readonly artifacts: ResultCollectionModel<ArtifactModel>;
}

interface JobLogRunModel {
  /** Lossless human-facing run number. */
  readonly number: string;
  readonly name: string;
  readonly href: string;
  readonly workflowName: string;
  readonly workflowHref: string;
  readonly attempt: number;
}

interface JobLogNavigationItemModel {
  readonly id: string;
  readonly name: string;
  readonly href: string | null;
  readonly status: StatusModel;
}

interface JobLogJobModel {
  readonly id: string;
  readonly name: string;
  readonly href: string;
  readonly attempt: number;
  readonly runnerLabel: string | null;
  readonly status: StatusModel;
  readonly startedAt: TimestampModel | null;
  readonly durationLabel: string | null;
}

type LogChannel = "stdout" | "stderr" | "system";

export interface JobLogLineModel {
  /** Stable identity used to derive a namespaced DOM anchor. */
  readonly id: string;
  /** Exact display sequence; represented as text so u64 values remain lossless. */
  readonly number: string;
  readonly timestamp: TimestampModel;
  readonly channel: LogChannel;
  readonly text: string;
}

interface JobLogSearchModel {
  readonly action: string;
  readonly query: string;
  readonly clearHref: string;
}

interface JobLogPaginationModel {
  readonly currentCursor: string | null;
  readonly previousCursor: string | null;
  readonly nextCursor: string | null;
  readonly label: string;
}

export interface JobLogPageModel {
  readonly kind: "job-log";
  readonly shell: ShellModel;
  readonly repository: RepositoryModel;
  readonly run: JobLogRunModel;
  readonly jobs: readonly JobLogNavigationItemModel[];
  readonly navigationPagination: PaginationModel;
  readonly job: JobLogJobModel;
  readonly search: JobLogSearchModel;
  readonly lines: readonly JobLogLineModel[];
  readonly notice: string | null;
  readonly pagination: JobLogPaginationModel;
}

export type PublicationAudience = "private" | "authenticated" | "public";

export interface RepositoryPublicationPolicyModel {
  readonly dashboard: PublicationAudience;
  readonly logs: PublicationAudience;
  readonly artifacts: PublicationAudience;
}

/**
 * Atomic capability required to render an update form. A missing capability
 * means the current policy remains visible but cannot be submitted.
 */
export interface RepositorySettingsUpdateModel {
  readonly action: string;
  readonly csrfToken: string;
}

export type RepositorySettingsArea = "access" | "secrets";

/** Only destinations the host has authorized for the current repository. */
export interface RepositorySettingsNavigationModel {
  readonly accessHref: string | null;
  readonly secretsHref: string | null;
  readonly current: RepositorySettingsArea;
}

interface RepositorySettingsPageBaseModel {
  readonly kind: "repository-settings";
  readonly shell: ShellModel;
  readonly repository: RepositorySettingsRepositoryModel;
  readonly heading: string;
  readonly summary: string;
  readonly settingsNavigation: RepositorySettingsNavigationModel;
  /** Lossless positive durable publication-policy revision. */
  readonly revision: string;
  readonly policy: RepositoryPublicationPolicyModel;
}

export interface RepositorySettingsPageModel extends RepositorySettingsPageBaseModel {
  readonly update: RepositorySettingsUpdateModel | null;
}

export type RepositorySecretNotice =
  | "created"
  | "replaced"
  | "deleted"
  | "provider-activated"
  | "conflict";

export type RepositorySecretState = "provisioning" | "active" | "disabled";
export type RepositorySecretProviderState =
  | "unconfigured"
  | "active"
  | "disabled";
export type RepositorySecretProviderHealth =
  | "unknown"
  | "healthy"
  | "degraded"
  | "unavailable";

interface RepositorySecretMutationEnvelopeModel {
  readonly action: string;
  readonly csrfToken: string;
  readonly expectedAuthorizationRevision: string;
}

export interface RepositorySecretProviderActivationModel
  extends RepositorySecretMutationEnvelopeModel {
  readonly expectedRevision: string;
}

export interface RepositorySecretProviderModel {
  readonly id: string;
  readonly state: RepositorySecretProviderState;
  readonly health: RepositorySecretProviderHealth;
  readonly activation: RepositorySecretProviderActivationModel | null;
}

export interface RepositorySecretCreateModel
  extends RepositorySecretMutationEnvelopeModel {
  readonly secretId: string;
  readonly mutationId: string;
}

export interface RepositorySecretReplaceModel
  extends RepositorySecretMutationEnvelopeModel {
  readonly mutationId: string;
}

export interface RepositorySecretDeleteModel
  extends RepositorySecretMutationEnvelopeModel {}

export interface RepositorySecretModel {
  readonly id: string;
  readonly name: string;
  readonly providerId: string;
  readonly state: RepositorySecretState;
  readonly currentVersion: string | null;
  /** Lossless positive durable secret-metadata revision. */
  readonly revision: string;
  readonly updatedAt: TimestampModel;
  readonly replace: RepositorySecretReplaceModel | null;
  readonly delete: RepositorySecretDeleteModel | null;
}

export interface RepositorySecretPaginationModel {
  readonly firstHref: string | null;
  readonly nextHref: string | null;
  readonly label: string;
}

export interface RepositorySecretsPageModel {
  readonly kind: "repository-secrets";
  readonly shell: ShellModel;
  readonly repository: RepositorySettingsRepositoryModel;
  readonly heading: string;
  readonly summary: string;
  readonly settingsNavigation: RepositorySettingsNavigationModel;
  readonly notice: RepositorySecretNotice | null;
  readonly maximumValueBytes: number;
  readonly provider: RepositorySecretProviderModel | null;
  readonly create: RepositorySecretCreateModel | null;
  readonly secrets: readonly RepositorySecretModel[];
  readonly pagination: RepositorySecretPaginationModel;
}

type RbacManagementArea = "users" | "roles" | "direct-bindings";
export type RbacManagementNotice = "saved" | "conflict" | "forbidden";

interface RbacMutationEnvelopeModel {
  readonly action: string;
  readonly csrfToken: string;
  readonly expectedAuthorizationRevision: string;
}

/** Host-owned navigation for the authenticated RBAC management surface. */
export interface RbacManagementNavigationModel {
  readonly usersHref: string;
  readonly rolesHref: string;
  readonly directBindingsHref: string;
  readonly current: RbacManagementArea;
}

export type ManagedUserStatus = "active" | "disabled";

export interface ManagedUserModel {
  /** Stable Automata-owned principal UUID. */
  readonly id: string;
  readonly href: string;
  /** Stable provider identifier, not an authority-bearing role label. */
  readonly providerId: string;
  readonly providerLogin: string;
  readonly displayName: string | null;
  readonly status: ManagedUserStatus;
}

type RbacBindingSource = "direct" | "provider-observed";
export type RbacBindingStatus = "active" | "revoked";

export type RbacScopeModel =
  | {
      readonly kind: "tenant";
      readonly label: string;
    }
  | {
      readonly kind: "repository";
      readonly label: string;
    }
  | {
      readonly kind: "runner-group";
      readonly label: string;
    };

interface UserRoleAssignmentModel {
  readonly bindingId: string;
  readonly bindingHref: string;
  readonly roleId: string;
  readonly roleHref: string;
  readonly roleName: string;
  readonly roleDisplayName: string;
  readonly scope: RbacScopeModel;
  readonly source: RbacBindingSource;
  readonly status: RbacBindingStatus;
  readonly validUntil: TimestampModel | null;
}

export interface UserListPageModel {
  readonly kind: "user-list";
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly users: readonly ManagedUserModel[];
  readonly notice: RbacManagementNotice | null;
  readonly pagination: PaginationModel;
}

export interface RbacMemberStatusUpdateModel extends RbacMutationEnvelopeModel {
  readonly expectedRevision: string;
  readonly operation: "disable" | "enable";
}

export interface UserDetailPageModel {
  readonly kind: "user-detail";
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly user: ManagedUserModel;
  readonly roleAssignments: readonly UserRoleAssignmentModel[];
  readonly notice: RbacManagementNotice | null;
  readonly statusUpdate: RbacMemberStatusUpdateModel | null;
}

type RbacRoleKind = "built-in" | "custom";

export interface RbacRoleSummaryModel {
  readonly id: string;
  readonly href: string;
  readonly name: string;
  readonly displayName: string;
  readonly kind: RbacRoleKind;
  readonly immutable: boolean;
  readonly permissionCount: number;
}

export interface RbacPermissionUpdateModel extends RbacMutationEnvelopeModel {
  readonly expectedRevision: string;
  readonly operation: "add" | "remove";
}

interface RbacPermissionModel {
  readonly name: string;
  readonly description: string;
  readonly granted: boolean;
  readonly update: RbacPermissionUpdateModel | null;
}

export interface RbacRoleCreateModel extends RbacMutationEnvelopeModel {}

export interface RbacRoleUpdateModel extends RbacMutationEnvelopeModel {
  readonly expectedRevision: string;
}

export interface RbacRoleDeleteModel extends RbacMutationEnvelopeModel {
  readonly expectedRevision: string;
}

export interface RoleListPageModel {
  readonly kind: "role-list";
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly roles: readonly RbacRoleSummaryModel[];
  readonly notice: RbacManagementNotice | null;
  readonly create: RbacRoleCreateModel | null;
  readonly pagination: PaginationModel;
}

export interface RoleDetailPageModel {
  readonly kind: "role-detail";
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly role: RbacRoleSummaryModel;
  readonly permissions: readonly RbacPermissionModel[];
  readonly notice: RbacManagementNotice | null;
  readonly update: RbacRoleUpdateModel | null;
  readonly delete: RbacRoleDeleteModel | null;
}

interface RbacBindingPrincipalModel {
  readonly id: string;
  readonly href: string;
  readonly label: string;
}

interface RbacBindingRoleModel {
  readonly id: string;
  readonly href: string;
  readonly name: string;
  readonly label: string;
}

export interface RbacBindingRevokeModel extends RbacMutationEnvelopeModel {
  readonly expectedRevision: string;
}

interface RbacBindingModel {
  readonly id: string;
  readonly revision: string;
  readonly principal: RbacBindingPrincipalModel;
  readonly role: RbacBindingRoleModel;
  readonly scope: RbacScopeModel;
  readonly source: RbacBindingSource;
  readonly status: RbacBindingStatus;
  readonly validUntil: TimestampModel | null;
  readonly revoke: RbacBindingRevokeModel | null;
}

interface RbacSelectOptionModel {
  readonly value: string;
  readonly label: string;
}

export interface RbacDirectGrantModel extends RbacMutationEnvelopeModel {
  readonly principals: readonly RbacSelectOptionModel[];
  readonly roles: readonly RbacSelectOptionModel[];
  readonly scopes: readonly RbacSelectOptionModel[];
}

export type RbacDirectBindingReadOnlyReason =
  | "management-unavailable"
  | "not-authorized"
  | "options-unavailable"
  | "options-overflow"
  | "no-options";

interface DirectBindingListPageBaseModel {
  readonly kind: "direct-binding-list";
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly bindings: readonly RbacBindingModel[];
  readonly notice: RbacManagementNotice | null;
  readonly pagination: PaginationModel;
}

export type DirectBindingListPageModel = DirectBindingListPageBaseModel &
  (
    | {
        readonly grant: RbacDirectGrantModel;
        readonly readOnlyReason: null;
      }
    | {
        readonly grant: null;
        readonly readOnlyReason: RbacDirectBindingReadOnlyReason;
      }
  );

export type PageModel =
  | SetupPageModel
  | RepositoryDirectoryPageModel
  | RunListPageModel
  | RunDetailPageModel
  | JobLogPageModel
  | RepositorySettingsPageModel
  | RepositorySecretsPageModel
  | UserListPageModel
  | UserDetailPageModel
  | RoleListPageModel
  | RoleDetailPageModel
  | DirectBindingListPageModel;

interface RenderAssets {
  /** Same-origin URL paths resolved by the host from Vite's client manifest. */
  readonly clientEntry: string;
  readonly stylesheets: readonly string[];
}

/**
 * Rendering data owned by the trusted HTTP host, rather than by a page model.
 * Keeping this separate prevents route data from selecting executable assets or
 * supplying document-level security attributes.
 */
interface RenderHostModel {
  readonly locale: string;
  readonly assets: RenderAssets;
  readonly cspNonce: string;
}

export interface RenderRequest {
  readonly schemaVersion: 1;
  readonly host: RenderHostModel;
  readonly page: PageModel;
}
