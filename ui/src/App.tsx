import type { ReactNode } from "react";
import type { PageModel } from "./models";
import type { LiveLogRecord } from "./liveLogs/sse";
import { ThemeToggle } from "./components/ThemeToggle";
import { JobLogPage } from "./pages/JobLogPage";
import { DeepLinkSignInPage } from "./pages/DeepLinkSignInPage";
import { RepositoryDirectoryPage } from "./pages/RepositoryDirectoryPage";
import { RepositorySettingsPage } from "./pages/RepositorySettingsPage";
import { RepositorySecretsPage } from "./pages/RepositorySecretsPage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunListPage } from "./pages/RunListPage";
import { DirectBindingPage } from "./pages/DirectBindingPage";
import { RoleDetailPage } from "./pages/RoleDetailPage";
import { RoleListPage } from "./pages/RoleListPage";
import { UserDetailPage } from "./pages/UserDetailPage";
import { UserListPage } from "./pages/UserListPage";
import { SetupPage } from "./pages/SetupPage";

export interface AppProps {
  readonly page: PageModel;
  readonly shellUtility?: ReactNode;
  /** Structured sample records used only by the standalone UI preview. */
  readonly initialJobLogRecords?: readonly LiveLogRecord[];
}

export function App({ page, shellUtility, initialJobLogRecords = [] }: AppProps) {
  const utility = shellUtility === undefined ? <ThemeToggle /> : shellUtility;

  switch (page.kind) {
    case "setup":
      return <SetupPage model={page} shellUtility={utility} />;
    case "repository-directory":
      return <RepositoryDirectoryPage model={page} shellUtility={utility} />;
    case "run-list":
      return <RunListPage model={page} shellUtility={utility} />;
    case "run-detail":
      return <RunDetailPage model={page} shellUtility={utility} />;
    case "job-log":
      return <JobLogPage initialRecords={initialJobLogRecords} model={page} shellUtility={utility} />;
    case "deep-link-sign-in":
      return <DeepLinkSignInPage model={page} shellUtility={utility} />;
    case "repository-settings":
      return <RepositorySettingsPage model={page} shellUtility={utility} />;
    case "repository-secrets":
      return <RepositorySecretsPage model={page} shellUtility={utility} />;
    case "user-list":
      return <UserListPage model={page} shellUtility={utility} />;
    case "user-detail":
      return <UserDetailPage model={page} shellUtility={utility} />;
    case "role-list":
      return <RoleListPage model={page} shellUtility={utility} />;
    case "role-detail":
      return <RoleDetailPage model={page} shellUtility={utility} />;
    case "direct-binding-list":
      return <DirectBindingPage model={page} shellUtility={utility} />;
    default:
      return assertNever(page);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unsupported page model: ${String(value)}`);
}
