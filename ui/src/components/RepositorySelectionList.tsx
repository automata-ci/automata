export interface SelectableProviderRepository {
  readonly defaultBranch: string;
  readonly id: string;
  readonly name: string;
  readonly owner: string;
  readonly private: boolean;
  readonly selected: boolean;
}

export interface RepositorySelectionListProps {
  readonly disabled?: boolean;
  readonly inputName?: string;
  readonly repositories: readonly SelectableProviderRepository[];
}

/** A transport-independent repository checklist for provider setup pages. */
export function RepositorySelectionList({
  disabled = false,
  inputName = "repository_ids",
  repositories,
}: RepositorySelectionListProps) {
  if (repositories.length === 0) {
    return (
      <p className="provider-repositories__empty">
        No repositories are available to this installation.
      </p>
    );
  }

  return (
    <fieldset className="provider-repositories" disabled={disabled}>
      <legend className="sr-only">Repositories</legend>
      <ul className="provider-repositories__list">
        {repositories.map((repository) => (
          <li className="provider-repositories__item" key={repository.id}>
            <label>
              <input
                className="choice-control"
                defaultChecked={repository.selected}
                name={inputName}
                type="checkbox"
                value={repository.id}
              />
              <span className="provider-repositories__identity">
                <span>
                  {repository.owner}/{repository.name}
                </span>
                <small>
                  {repository.private ? "Private" : "Public"}
                  {" · default branch "}
                  {repository.defaultBranch}
                </small>
              </span>
            </label>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}
