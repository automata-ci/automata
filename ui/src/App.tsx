import type { ReactNode } from "react";
import type { PageModel } from "./models";
import type { LiveLogRecord } from "./logs/sse";
import type { LiveLogAccessProvider } from "./logs/protocol";
import { ThemeToggle } from "./components/ThemeToggle";
import { JobLogPage } from "./pages/JobLogPage";
import { DeepLinkSignInPage } from "./pages/DeepLinkSignInPage";
import { RepositoryDirectoryPage } from "./pages/RepositoryDirectoryPage";
import { RunnerDirectoryPage } from "./pages/RunnerDirectoryPage";
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
  /** Host-supplied direct log authority for composed deployments such as Cloud. */
  readonly jobLogAccess?: LiveLogAccessProvider;
}

export function App({ jobLogAccess, page, shellUtility }: AppProps) {
  const utility = shellUtility === undefined ? <ThemeToggle /> : shellUtility;

  switch (page.kind) {
    case "setup":
      return <SetupPage model={page} shellUtility={utility} />;
    case "repository-directory":
      return <RepositoryDirectoryPage model={page} shellUtility={utility} />;
    case "runner-directory":
      return <RunnerDirectoryPage model={page} shellUtility={utility} />;
    case "run-list":
      return <RunListPage model={page} shellUtility={utility} />;
    case "run-detail":
      return <RunDetailPage model={page} shellUtility={utility} />;
    case "job-log":
      return (
        <JobLogPage
          {...(jobLogAccess === undefined ? {} : { access: jobLogAccess })}
          model={page}
          shellUtility={utility}
        />
      );
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

interface PreviewAppProps extends AppProps {
  readonly initialJobLogRecords: readonly LiveLogRecord[];
}

/** Keeps standalone sample data outside the production App contract. */
export function PreviewApp({
  initialJobLogRecords,
  page,
  shellUtility,
}: PreviewAppProps) {
  if (page.kind === "job-log") {
    return (
      <JobLogPage
        initialRecords={initialJobLogRecords}
        model={page}
        shellUtility={shellUtility}
      />
    );
  }
  return <App page={page} shellUtility={shellUtility} />;
}

function assertNever(value: never): never {
  throw new Error(`Unsupported page model: ${String(value)}`);
}
