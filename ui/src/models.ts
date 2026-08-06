export type StatusTone =
  | "neutral"
  | "queued"
  | "running"
  | "success"
  | "failure"
  | "warning";

export interface TimestampModel {
  readonly iso: string;
  readonly label: string;
}

export interface ViewerModel {
  readonly displayName: string;
  readonly profileHref: string;
}

export interface NavigationItemModel {
  readonly label: string;
  readonly href: string;
  readonly current?: boolean;
}

export interface ShellModel {
  readonly productName: string;
  readonly homeHref: string;
  readonly signInHref: string;
  readonly documentTitle: string;
  readonly description: string;
  readonly viewer: ViewerModel | null;
  readonly navigation: readonly NavigationItemModel[];
}

export interface RepositoryModel {
  readonly owner: string;
  readonly name: string;
  readonly href: string;
  readonly runsHref: string;
}

export interface StatusModel {
  readonly label: string;
  readonly tone: StatusTone;
}

export interface CommitModel {
  readonly shortSha: string;
  readonly message: string;
  readonly href: string;
}

export interface RunListItemModel {
  readonly id: string;
  readonly name: string;
  readonly workflowName: string;
  readonly href: string;
  readonly status: StatusModel;
  readonly branch: string;
  readonly event: string;
  readonly actor: string;
  readonly commit: CommitModel;
  readonly startedAt: TimestampModel;
  readonly durationLabel: string;
}

export interface FilterOptionModel {
  readonly value: string;
  readonly label: string;
}

export interface RunFiltersModel {
  readonly action: string;
  readonly status: string;
  readonly branch: string;
  readonly statusOptions: readonly FilterOptionModel[];
  readonly clearHref: string;
}

export interface PaginationModel {
  readonly previousHref: string | null;
  readonly nextHref: string | null;
  readonly label: string;
}

export interface RunListPageModel {
  readonly kind: "run-list";
  readonly shell: ShellModel;
  readonly repository: RepositoryModel;
  readonly heading: string;
  readonly summary: string;
  readonly filters: RunFiltersModel;
  readonly runs: readonly RunListItemModel[];
  readonly pagination: PaginationModel;
}

export interface StepModel {
  readonly number: number;
  readonly name: string;
  readonly status: StatusModel;
  readonly durationLabel: string;
  readonly logHref: string;
}

export interface JobModel {
  readonly id: string;
  readonly name: string;
  readonly href: string;
  readonly runnerLabel: string;
  readonly status: StatusModel;
  readonly startedAt: TimestampModel | null;
  readonly durationLabel: string;
  readonly steps: readonly StepModel[];
}

export interface ArtifactModel {
  readonly id: string;
  readonly name: string;
  readonly sizeLabel: string;
  readonly digest: string;
  readonly downloadHref: string;
  readonly expiresAt: TimestampModel;
}

export interface RunOperationModel {
  readonly label: string;
  readonly action: string;
  readonly style: "primary" | "danger" | "secondary";
  readonly confirmation?: string;
}

export interface RunDetailModel {
  readonly id: string;
  readonly name: string;
  readonly workflowName: string;
  readonly workflowHref: string;
  readonly status: StatusModel;
  readonly branch: string;
  readonly branchHref: string;
  readonly event: string;
  readonly actor: string;
  readonly commit: CommitModel;
  readonly createdAt: TimestampModel;
  readonly durationLabel: string;
  readonly attempt: number;
}

export interface RunDetailPageModel {
  readonly kind: "run-detail";
  readonly shell: ShellModel;
  readonly repository: RepositoryModel;
  readonly run: RunDetailModel;
  readonly csrfToken: string;
  readonly operations: readonly RunOperationModel[];
  readonly jobs: readonly JobModel[];
  readonly artifacts: readonly ArtifactModel[];
}

export type PageModel = RunListPageModel | RunDetailPageModel;

export interface RenderAssets {
  /** Same-origin URL paths resolved by the host from Vite's client manifest. */
  readonly clientEntry: string;
  readonly stylesheets: readonly string[];
}

/**
 * Rendering data owned by the trusted HTTP host, rather than by a page model.
 * Keeping this separate prevents route data from selecting executable assets or
 * supplying document-level security attributes.
 */
export interface RenderHostModel {
  readonly locale: string;
  readonly assets: RenderAssets;
  readonly cspNonce?: string;
}

export interface RenderRequest {
  readonly schemaVersion: 1;
  readonly host: RenderHostModel;
  readonly page: PageModel;
}
