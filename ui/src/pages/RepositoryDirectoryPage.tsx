import type { ReactNode } from "react";
import type {
  RepositoryDirectoryItemModel,
  RepositoryDirectoryPageModel,
} from "../models";
import { EmptyState } from "../components/EmptyState";
import { Icon } from "../components/Icon";
import { Shell } from "../components/Shell";

export interface RepositoryDirectoryPageProps {
  readonly model: RepositoryDirectoryPageModel;
  readonly shellUtility?: ReactNode;
}

export function RepositoryDirectoryPage({
  model,
  shellUtility,
}: RepositoryDirectoryPageProps) {
  const signInForm =
    model.shell.viewer === null && model.shell.signIn !== null ? (
      <form action={model.shell.signIn.action} method="post">
        <input name="return_path" type="hidden" value={model.shell.signIn.returnPath} />
        <button className="button" type="submit">
          Sign in
        </button>
      </form>
    ) : undefined;

  return (
    <Shell shell={model.shell} repository={null} utility={shellUtility}>
      <main className="layout-width page" id="main-content" tabIndex={-1}>
        <header className="page-heading">
          <div>
            <h1>{model.heading}</h1>
            <p>{model.summary}</p>
          </div>
        </header>
        <section aria-labelledby="repository-list-heading" className="panel repository-directory">
          <div className="panel__heading">
            <h2 id="repository-list-heading">Available repositories</h2>
            <span>{model.pagination.label}</span>
          </div>
          {model.repositories.length === 0 ? (
            <EmptyState
              action={signInForm}
              description="No repositories are available to you."
              heading="No repositories available"
              headingLevel="h3"
              icon="repository"
            />
          ) : (
            <ul className="repository-directory__list">
              {model.repositories.map((repository) => (
                <RepositoryRow
                  key={`${repository.owner.toLowerCase()}/${repository.name.toLowerCase()}`}
                  repository={repository}
                />
              ))}
            </ul>
          )}
        </section>
        {model.pagination.nextHref === null ? null : (
          <nav aria-label="Repository pages" className="standalone-pagination">
            <a className="button button--quiet" href={model.pagination.nextHref} rel="next">
              Next page
            </a>
          </nav>
        )}
      </main>
    </Shell>
  );
}

function RepositoryRow({ repository }: { readonly repository: RepositoryDirectoryItemModel }) {
  const secretsHref = `/${repository.owner}/${repository.name}/settings/secrets`;
  const settingsLabel = repository.settingsHref === secretsHref ? "Secrets" : "Access";
  const primaryHref = repository.actionsHref ?? repository.sourceHref;

  return (
    <li className="repository-directory__item">
      <div className="repository-directory__identity">
        <span className="repository-directory__icon" aria-hidden="true">
          <Icon name="repository" size={18} />
        </span>
        <div>
          <a
            className="repository-directory__name"
            href={primaryHref}
            rel={repository.actionsHref === null ? "noreferrer" : undefined}
            target={repository.actionsHref === null ? "_blank" : undefined}
          >
            <span>{repository.owner}</span>
            <span>/</span>
            <strong>{repository.name}</strong>
          </a>
          <span className="repository-directory__source">GitHub repository</span>
        </div>
      </div>
      <nav
        aria-label={`${repository.owner}/${repository.name} destinations`}
        className="repository-directory__destinations"
      >
        <a
          className="button button--quiet"
          href={repository.sourceHref}
          rel="noreferrer"
          target="_blank"
        >
          <Icon name="overview" />
          Code
          <Icon name="external-link" size={14} />
        </a>
        {repository.actionsHref === null ? null : (
          <a className="button button--quiet" href={repository.actionsHref}>
            <Icon name="actions" />
            Actions
          </a>
        )}
        {repository.settingsHref === null ? null : (
          <a className="button button--quiet" href={repository.settingsHref}>
            <Icon name="settings" />
            {settingsLabel}
          </a>
        )}
      </nav>
    </li>
  );
}
