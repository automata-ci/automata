import type { PropsWithChildren } from "react";
import type { RepositoryModel, ShellModel } from "../models";

interface ShellProps extends PropsWithChildren {
  readonly shell: ShellModel;
  readonly repository?: RepositoryModel;
}

export function Shell({ shell, repository, children }: ShellProps) {
  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="site-header">
        <div className="site-header__inner">
          <a className="wordmark" href={shell.homeHref} aria-label={`${shell.productName} home`}>
            <span className="wordmark__mark" aria-hidden="true">
              A
            </span>
            <span>{shell.productName}</span>
          </a>
          <nav className="primary-nav" aria-label="Primary navigation">
            {shell.navigation.map((item) => (
              <a
                href={item.href}
                key={item.href}
                aria-current={item.current ? "page" : undefined}
              >
                {item.label}
              </a>
            ))}
          </nav>
          {shell.viewer === null ? (
            <a className="viewer-link" href={shell.signInHref}>
              Sign in
            </a>
          ) : (
            <a className="viewer-link" href={shell.viewer.profileHref}>
              <span className="viewer-link__avatar" aria-hidden="true">
                {shell.viewer.displayName.slice(0, 1).toUpperCase()}
              </span>
              <span>{shell.viewer.displayName}</span>
            </a>
          )}
        </div>
      </header>
      {repository === undefined ? null : (
        <div className="repo-bar">
          <div className="layout-width">
            <a href={repository.href}>
              <span>{repository.owner}</span>
              <span aria-hidden="true"> / </span>
              <strong>{repository.name}</strong>
            </a>
          </div>
        </div>
      )}
      {children}
      <footer className="site-footer">
        <div className="layout-width">
          <span>{shell.productName}</span>
          <span>Workflow execution with GitHub Actions compatibility.</span>
        </div>
      </footer>
    </>
  );
}
