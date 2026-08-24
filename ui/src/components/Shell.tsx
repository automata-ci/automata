import {
  createContext,
  useContext,
  type PropsWithChildren,
  type ReactNode,
} from "react";
import type { RepositoryModel, ShellModel } from "../models";
import { isVisibleDisplayCodePoint } from "../unicode";
import { AutomataMark } from "./AutomataMark";
import { Icon } from "./Icon";

export interface ShellFooterLink {
  readonly href: string;
  readonly label: string;
}

export interface ShellFooterLinksProviderProps extends PropsWithChildren {
  readonly links: readonly ShellFooterLink[];
}

const ShellFooterLinksContext = createContext<readonly ShellFooterLink[]>([]);

export function ShellFooterLinksProvider({
  children,
  links,
}: ShellFooterLinksProviderProps) {
  return (
    <ShellFooterLinksContext.Provider value={links}>
      {children}
    </ShellFooterLinksContext.Provider>
  );
}

export interface ShellProps extends PropsWithChildren {
  readonly shell: ShellModel;
  readonly repository: RepositoryModel | null;
  readonly currentRepositoryView?: "actions" | "settings";
  readonly footerLinks?: readonly ShellFooterLink[];
  readonly utility?: ReactNode;
}

export function Shell({
  shell,
  repository,
  currentRepositoryView = "actions",
  footerLinks,
  utility,
  children,
}: ShellProps) {
  const inheritedFooterLinks = useContext(ShellFooterLinksContext);
  const resolvedFooterLinks = footerLinks ?? inheritedFooterLinks;
  const viewerInitial = shell.viewer === null
    ? null
    : firstUppercaseCodePoint(shell.viewer.displayName);
  const hasViewerMenu =
    shell.viewer !== null &&
    (shell.accountNavigation.length !== 0 || shell.signOut !== null);

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="site-header">
        <div className="site-header__inner">
          <a className="wordmark" href={shell.homeHref} aria-label={`${shell.productName} home`}>
            <span className="wordmark__mark" aria-hidden="true">
              <AutomataMark />
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
            ) : shell.viewer === null ? null : !hasViewerMenu ? (
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
                  <Icon
                    className="viewer-menu__chevron"
                    name="chevron-down"
                    size={14}
                  />
                  <span className="sr-only">
                    {shell.viewer.displayName} account menu
                  </span>
                </summary>
                <div className="viewer-menu__popover">
                  <div className="viewer-menu__identity">
                    <span
                      className="viewer-menu__avatar viewer-link__avatar"
                      aria-hidden="true"
                    >
                      {viewerInitial}
                    </span>
                    <strong
                      className="viewer-menu__name"
                      title={shell.viewer.displayName}
                    >
                      {shell.viewer.displayName}
                    </strong>
                  </div>
                  <hr className="viewer-menu__divider" />
                  {shell.accountNavigation.length === 0 ? null : (
                    <nav
                      className="viewer-menu__navigation"
                      aria-label="Account navigation"
                    >
                      {shell.accountNavigation.map((item) => (
                        <a href={item.href} key={`${item.icon}:${item.href}`}>
                          <Icon name={item.icon} />
                          <span>{item.label}</span>
                        </a>
                      ))}
                    </nav>
                  )}
                  {shell.signOut === null ? null : (
                    <>
                      {shell.accountNavigation.length === 0 ? null : (
                        <hr className="viewer-menu__divider" />
                      )}
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
                    </>
                  )}
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
            <a href={repository.runsHref}>
              <span>{repository.owner}</span>
              <span className="repo-header__separator" aria-hidden="true">
                /
              </span>
              <span className="sr-only">/</span>
              <strong>{repository.name}</strong>
            </a>
          </div>
          <nav className="repo-nav layout-wide" aria-label="Repository navigation">
            <a href={repository.sourceHref} rel="noreferrer" target="_blank">
              <Icon name="overview" />
              Code
              <Icon name="external-link" size={14} />
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
        <div className="site-footer__inner layout-width">
          <a className="site-footer__brand" href={shell.homeHref}>
            <AutomataMark className="site-footer__mark" />
            <span className="site-footer__brand-label">
              {shell.productName}
            </span>
          </a>
          {resolvedFooterLinks.length === 0 ? null : (
            <nav
              className="site-footer__navigation"
              aria-label="Footer navigation"
            >
              {resolvedFooterLinks.map((item) => (
                <a href={item.href} key={`${item.label}:${item.href}`}>
                  {item.label}
                </a>
              ))}
            </nav>
          )}
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
