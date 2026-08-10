import type { PropsWithChildren, ReactNode } from "react";
import type { RepositoryModel, ShellModel } from "../models";
import { isVisibleDisplayCodePoint } from "../unicode";
import { Icon } from "./Icon";

interface ShellProps extends PropsWithChildren {
  readonly shell: ShellModel;
  readonly repository: RepositoryModel | null;
  readonly currentRepositoryView?: "actions" | "settings";
  readonly utility?: ReactNode;
}

export function Shell({
  shell,
  repository,
  currentRepositoryView = "actions",
  utility,
  children,
}: ShellProps) {
  const viewerInitial = shell.viewer === null
    ? null
    : firstUppercaseCodePoint(shell.viewer.displayName);

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="site-header">
        <div className="site-header__inner">
          <a className="wordmark" href={shell.homeHref} aria-label={`${shell.productName} home`}>
            <span className="wordmark__mark" aria-hidden="true">
              <Icon name="workflow" size={18} />
            </span>
            <span className="wordmark__label">{shell.productName}</span>
          </a>
          <nav className="primary-nav" aria-label="Primary navigation">
            {shell.navigation.map((item) => (
              <a
                href={item.href}
                key={`${item.label}:${item.href}`}
                aria-current={item.current ? "page" : undefined}
              >
                {item.label}
              </a>
            ))}
          </nav>
          <div className="site-header__tools">
            {utility}
            {shell.viewer === null && shell.signIn !== null ? (
              <form action={shell.signIn.action} method="post">
                <input
                  name="return_path"
                  type="hidden"
                  value={shell.signIn.returnPath}
                />
                <button className="viewer-link" type="submit">
                  Sign in
                </button>
              </form>
            ) : shell.viewer === null ? null : shell.signOut === null ? (
              <span className="viewer-link">
                <span className="viewer-link__avatar" aria-hidden="true">
                  {viewerInitial}
                </span>
                <span className="viewer-link__name">{shell.viewer.displayName}</span>
              </span>
            ) : (
              <details className="viewer-menu">
                <summary className="viewer-link">
                  <span className="viewer-link__avatar" aria-hidden="true">
                    {viewerInitial}
                  </span>
                  <span className="viewer-link__name">{shell.viewer.displayName}</span>
                  <Icon
                    className="viewer-menu__chevron"
                    name="chevron-down"
                    size={14}
                  />
                  <span className="sr-only"> account menu</span>
                </summary>
                <div className="viewer-menu__popover">
                  <p className="viewer-menu__identity">
                    Signed in as <strong>{shell.viewer.displayName}</strong>
                  </p>
                  <form action={shell.signOut.action} method="post">
                    <input
                      name="csrf_token"
                      type="hidden"
                      value={shell.signOut.csrfToken}
                    />
                    <button className="viewer-menu__sign-out" type="submit">
                      <Icon name="sign-out" />
                      <span>Sign out</span>
                    </button>
                  </form>
                </div>
              </details>
            )}
          </div>
        </div>
      </header>
      {repository === null ? null : (
        <div className="repo-header">
          <div className="repo-header__identity layout-wide">
            <Icon name="repository" size={18} />
            <a href={repository.sourceHref}>
              <span>{repository.owner}</span>
              <span className="repo-header__separator" aria-hidden="true">
                /
              </span>
              <span className="sr-only">/</span>
              <strong>{repository.name}</strong>
            </a>
          </div>
          <nav className="repo-nav layout-wide" aria-label="Repository navigation">
            <a href={repository.sourceHref}>
              <Icon name="overview" />
              Code
            </a>
            <a
              href={repository.runsHref}
              aria-current={currentRepositoryView === "actions" ? "page" : undefined}
            >
              <Icon name="actions" />
              Actions
            </a>
            {repository.settingsHref === null ? null : (
              <a
                href={repository.settingsHref}
                aria-current={
                  currentRepositoryView === "settings" ? "page" : undefined
                }
              >
                <Icon name="settings" />
                Settings
              </a>
            )}
          </nav>
        </div>
      )}
      {children}
      <footer className="site-footer">
        <div className="layout-width">
          <span>{shell.productName}</span>
        </div>
      </footer>
    </>
  );
}

function firstUppercaseCodePoint(displayName: string): string {
  const firstCodePoint =
    Array.from(displayName).find(isVisibleDisplayCodePoint) ?? "?";
  return Array.from(firstCodePoint.toUpperCase())[0] ?? "?";
}
