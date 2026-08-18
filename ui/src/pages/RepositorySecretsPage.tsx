import type { ReactNode } from "react";
import { AuthorizationMutationFields } from "../components/AuthorizationMutationFields";
import { EmptyState } from "../components/EmptyState";
import { RepositorySettingsNavigation } from "../components/RepositorySettingsNavigation";
import { Shell } from "../components/Shell";
import { enforceUtf8ByteLimit } from "../components/textInputConstraints";
import type {
  RepositorySecretCreateModel,
  RepositorySecretModel,
  RepositorySecretNotice,
  RepositorySecretProviderModel,
  RepositorySecretsPageModel,
} from "../models";

export function RepositorySecretsPage({
  model,
  shellUtility,
}: {
  readonly model: RepositorySecretsPageModel;
  readonly shellUtility?: ReactNode;
}) {
  const readOnly =
    model.create === null &&
    model.provider?.activation == null &&
    model.secrets.every(
      (secret) => secret.replace === null && secret.delete === null,
    );
  return (
    <Shell
      currentRepositoryView="settings"
      repository={model.repository}
      shell={model.shell}
      utility={shellUtility}
    >
      <main className="layout-width page" id="main-content" tabIndex={-1}>
        <header className="page-heading">
          <div>
            <h1>{model.heading}</h1>
            <p>{model.summary}</p>
          </div>
        </header>

        <RepositorySettingsNavigation navigation={model.settingsNavigation} />
        {model.notice === null ? null : <SecretNotice notice={model.notice} />}
        {readOnly ? (
          <p className="repository-secret-read-only" role="note">
            Read-only: you can review secret metadata, but secret values and
            mutation controls are not available from this page.
          </p>
        ) : null}
        {model.provider === null ? null : (
          <SecretProvider provider={model.provider} />
        )}
        {model.create === null ? null : (
          <SecretCreateForm
            capability={model.create}
            maximumValueBytes={model.maximumValueBytes}
          />
        )}

        <section aria-labelledby="repository-secret-list-heading" className="panel">
          <div className="panel__heading">
            <h2 id="repository-secret-list-heading">Repository secrets</h2>
            <span>{model.pagination.label}</span>
          </div>
          {model.secrets.length === 0 ? (
            <EmptyState
              description={
                model.create === null
                  ? "No repository secrets are available to you."
                  : "Create a repository secret to store an encrypted value for future workflow delivery."
              }
              heading="No secrets yet"
              icon="settings"
            />
          ) : (
            <ul className="repository-secret-list">
              {model.secrets.map((secret) => (
                <SecretRow
                  key={secret.id}
                  maximumValueBytes={model.maximumValueBytes}
                  secret={secret}
                />
              ))}
            </ul>
          )}
        </section>

        {model.pagination.firstHref === null &&
        model.pagination.nextHref === null ? null : (
          <nav aria-label="Secret pages" className="standalone-pagination">
            {model.pagination.firstHref === null ? null : (
              <a className="button" href={model.pagination.firstHref}>
                First page
              </a>
            )}
            {model.pagination.nextHref === null ? null : (
              <a className="button" href={model.pagination.nextHref}>
                Next page
              </a>
            )}
          </nav>
        )}
      </main>
    </Shell>
  );
}

function SecretNotice({ notice }: { readonly notice: RepositorySecretNotice }) {
  const message = {
    created: "Secret created.",
    replaced: "Secret value replaced.",
    deleted: "Secret deleted.",
    "provider-activated": "Encrypted secret storage activated.",
    conflict: "Secret metadata changed. Review the current state before trying again.",
  }[notice];
  return (
    <p
      className={`repository-secret-notice repository-secret-notice--${notice}`}
      role={notice === "conflict" ? "alert" : "status"}
    >
      {message}
    </p>
  );
}

function SecretProvider({
  provider,
}: {
  readonly provider: RepositorySecretProviderModel;
}) {
  const stateLabel = humanize(provider.state);
  const healthLabel = humanize(provider.health);
  return (
    <section aria-labelledby="secret-provider-heading" className="panel repository-secret-provider">
      <div className="panel__heading">
        <h2 id="secret-provider-heading">Encrypted storage</h2>
        <span>{stateLabel}</span>
      </div>
      <div className="repository-secret-provider__body">
        <div>
          <p>
            Secret values are encrypted before durable storage and are never
            shown again after submission.
          </p>
          <dl className="repository-secret-provider__metadata">
            <div>
              <dt>Provider</dt>
              <dd>{provider.id}</dd>
            </div>
            <div>
              <dt>Health</dt>
              <dd className={`repository-secret-health repository-secret-health--${provider.health}`}>
                {healthLabel}
              </dd>
            </div>
          </dl>
        </div>
        {provider.activation === null ? null : (
          <form action={provider.activation.action} method="post">
            <AuthorizationMutationFields capability={provider.activation} />
            <input
              name="expected_revision"
              type="hidden"
              value={provider.activation.expectedRevision}
            />
            <button className="button button--primary" type="submit">
              Activate storage
            </button>
          </form>
        )}
      </div>
    </section>
  );
}

function SecretCreateForm({
  capability,
  maximumValueBytes,
}: {
  readonly capability: RepositorySecretCreateModel;
  readonly maximumValueBytes: number;
}) {
  return (
    <section aria-labelledby="create-secret-heading" className="panel repository-secret-create">
      <div className="panel__heading">
        <h2 id="create-secret-heading">Create secret</h2>
      </div>
      <form action={capability.action} method="post">
        <AuthorizationMutationFields capability={capability} />
        <input name="secret_id" type="hidden" value={capability.secretId} />
        <input name="mutation_id" type="hidden" value={capability.mutationId} />
        <div className="repository-secret-form-grid">
          <label>
            <span>Name</span>
            <input
              autoCapitalize="characters"
              autoComplete="off"
              className="form-control"
              maxLength={255}
              name="name"
              pattern="(?!(?:GITHUB|ACTIONS|RUNNER|AUTOMATA)_)[A-Z_][A-Z0-9_]*"
              required
              spellCheck={false}
              type="text"
            />
            <small>
              Uppercase letters, digits, and underscores. GitHub, Actions,
              Runner, and Automata prefixes are reserved.
            </small>
          </label>
          <SecretValueInput
            id="new-secret-value"
            maximumValueBytes={maximumValueBytes}
          />
        </div>
        <div className="repository-secret-form-actions">
          <p>The value is accepted once and cannot be retrieved from this page.</p>
          <button className="button button--primary" type="submit">
            Create secret
          </button>
        </div>
      </form>
    </section>
  );
}

function SecretRow({
  maximumValueBytes,
  secret,
}: {
  readonly maximumValueBytes: number;
  readonly secret: RepositorySecretModel;
}) {
  const hasMutation = secret.replace !== null || secret.delete !== null;
  return (
    <li className="repository-secret-row">
      <div className="repository-secret-row__summary">
        <div className="repository-secret-row__identity">
          <strong>{secret.name}</strong>
          <span className={`repository-secret-state repository-secret-state--${secret.state}`}>
            {humanize(secret.state)}
          </span>
        </div>
        <dl className="repository-secret-row__metadata">
          <div>
            <dt>Version</dt>
            <dd>{secret.currentVersion === null ? "Not available" : secret.currentVersion}</dd>
          </div>
          <div>
            <dt>Provider</dt>
            <dd>{secret.providerId}</dd>
          </div>
          <div>
            <dt>Updated</dt>
            <dd>
              <time dateTime={secret.updatedAt.iso}>{secret.updatedAt.label}</time>
            </dd>
          </div>
        </dl>
      </div>
      {hasMutation ? (
        <details className="repository-secret-row__manage">
          <summary>Manage</summary>
          <div className="repository-secret-row__controls">
            {secret.replace === null ? null : (
              <form action={secret.replace.action} method="post">
                <AuthorizationMutationFields capability={secret.replace} />
                <input name="mutation_id" type="hidden" value={secret.replace.mutationId} />
                <input name="name" type="hidden" value={secret.name} />
                <input name="expected_revision" type="hidden" value={secret.revision} />
                <SecretValueInput
                  id={`replace-secret-${secret.id}`}
                  maximumValueBytes={maximumValueBytes}
                />
                <button className="button button--primary" type="submit">
                  Replace value
                </button>
              </form>
            )}
            {secret.delete === null ? null : (
              <form action={secret.delete.action} className="repository-secret-delete" method="post">
                <AuthorizationMutationFields capability={secret.delete} />
                <input name="expected_revision" type="hidden" value={secret.revision} />
                <p>
                  This revokes access immediately and schedules retained
                  encrypted versions for deletion.
                </p>
                <button className="button button--danger" type="submit">
                  Delete secret
                </button>
              </form>
            )}
          </div>
        </details>
      ) : null}
    </li>
  );
}

function SecretValueInput({
  id,
  maximumValueBytes,
}: {
  readonly id: string;
  readonly maximumValueBytes: number;
}) {
  return (
    <label htmlFor={id}>
      <span>Value</span>
      <input
        autoCapitalize="none"
        autoComplete="new-password"
        className="form-control"
        id={id}
        maxLength={maximumValueBytes}
        name="value"
        onInput={(event) =>
          enforceUtf8ByteLimit(event.currentTarget, maximumValueBytes)
        }
        required
        spellCheck={false}
        type="password"
      />
      <small>Maximum 64 KiB. The value is never returned to your browser.</small>
    </label>
  );
}

function humanize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1).replaceAll("-", " ");
}
