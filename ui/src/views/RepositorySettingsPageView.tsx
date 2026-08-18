import type { ReactNode } from "react";
import type {
  PublicationAudience,
  RepositoryPublicationPolicyModel,
  RepositorySettingsPageModel,
} from "../models";
import type { PublicationPolicyFormState } from "../viewModels/publicationPolicy";
import { RepositorySettingsNavigation } from "../components/RepositorySettingsNavigation";
import { Shell } from "../components/Shell";

export interface RepositorySettingsPageViewProps {
  readonly form: PublicationPolicyFormState;
  readonly model: RepositorySettingsPageModel;
  readonly shellUtility?: ReactNode;
}

interface AudienceOption {
  readonly label: string;
  readonly description: string;
}

const audienceValues = ["private", "authenticated", "public"] as const;

const audienceOptions: Readonly<Record<PublicationAudience, AudienceOption>> = {
  private: {
    label: "Private",
    description: "Only users with the required repository permission can access it.",
  },
  authenticated: {
    label: "Signed-in users",
    description: "Anyone signed in to this Automata tenant can access it.",
  },
  public: {
    label: "Public",
    description: "Anyone can access it without signing in. This never grants write access.",
  },
};

const publicationResources: readonly {
  readonly field: keyof RepositoryPublicationPolicyModel;
  readonly formName: string;
  readonly label: string;
  readonly description: string;
}[] = [
  { field: "dashboard", formName: "dashboard_audience", label: "Run pages", description: "Repository, workflow, run, and job details." },
  { field: "logs", formName: "log_audience", label: "Job logs", description: "Console output recorded for workflow jobs." },
  { field: "artifacts", formName: "artifact_audience", label: "Artifacts", description: "Artifact names, metadata, and file downloads." },
];

export function RepositorySettingsPageView({
  form,
  model,
  shellUtility,
}: RepositorySettingsPageViewProps) {
  return (
    <Shell currentRepositoryView="settings" repository={model.repository} shell={model.shell} utility={shellUtility}>
      <main className="layout-width page" id="main-content" tabIndex={-1}>
        <header className="page-heading"><div><h1>{model.heading}</h1><p>{model.summary}</p></div></header>
        <RepositorySettingsNavigation navigation={model.settingsNavigation} />
        <section className="panel repository-settings" aria-labelledby="publication-settings-heading">
          <div className="panel__heading"><h2 id="publication-settings-heading">Defaults for new runs</h2></div>
          <div className="repository-settings__guidance" id="publication-policy-guidance">
            <p>These defaults are recorded when a workflow run starts. Existing runs keep their current access.</p>
            <p>Run pages, logs, and artifacts are authorized independently. When a job can read Automata-managed secrets, its logs and artifacts remain private.</p>
          </div>
          {model.update === null ? (
            <div>
              <p className="repository-settings__notice" role="note">Read-only: you can review these defaults, but they cannot be changed from this page.</p>
              <AudienceSummary policy={model.policy} />
              <div className="repository-settings__actions"><a className="button" href={model.repository.runsHref}>Back to workflow runs</a></div>
            </div>
          ) : (
            <form action={model.update.action} aria-busy={form.isSubmitting || undefined} aria-describedby="publication-policy-guidance" method="post" onSubmit={form.onSubmit}>
              <input name="csrf_token" type="hidden" value={model.update.csrfToken} />
              <input name="expected_revision" type="hidden" value={model.revision} />
              <AudienceControls onChange={form.onChange} policy={form.draftPolicy} />
              <div className="repository-settings__actions">
                <button aria-busy={form.isSubmitting || undefined} className="button button--primary repository-settings__save" disabled={form.saveDisabled} type="submit">
                  {form.isSubmitting ? "Saving…" : "Save changes"}
                </button>
              </div>
            </form>
          )}
        </section>
      </main>
    </Shell>
  );
}

function AudienceSummary({ policy }: { readonly policy: RepositoryPublicationPolicyModel }) {
  return (
    <ul aria-label="Current access defaults" className="repository-settings__summary">
      {publicationResources.map((resource) => {
        const option = audienceOptions[policy[resource.field]];
        return (
          <li className="audience-summary" key={resource.field}>
            <div className="audience-summary__resource"><h3>{resource.label}</h3><p>{resource.description}</p></div>
            <div className="audience-summary__current"><strong><span className="sr-only">Current access: </span>{option.label}</strong><span>{option.description}</span></div>
          </li>
        );
      })}
    </ul>
  );
}

function AudienceControls({
  onChange,
  policy,
}: {
  readonly onChange: (field: keyof RepositoryPublicationPolicyModel, value: PublicationAudience) => void;
  readonly policy: RepositoryPublicationPolicyModel;
}) {
  return (
    <div className="repository-settings__resources">
      {publicationResources.map((resource) => {
        const descriptionId = `${resource.field}-audience-description`;
        return (
          <fieldset aria-describedby={descriptionId} className="audience-setting" key={resource.field}>
            <legend>{resource.label}</legend><p id={descriptionId}>{resource.description}</p>
            <div className="audience-options">
              {audienceValues.map((value) => {
                const option = audienceOptions[value];
                const inputId = `${resource.field}-audience-${value}`;
                return (
                  <label className="audience-option" htmlFor={inputId} key={value}>
                    <input checked={policy[resource.field] === value} className="choice-control" id={inputId} name={resource.formName} onChange={() => onChange(resource.field, value)} required type="radio" value={value} />
                    <span><strong>{option.label}</strong><small>{option.description}</small></span>
                  </label>
                );
              })}
            </div>
          </fieldset>
        );
      })}
    </div>
  );
}
