import type { ReactNode } from "react";
import { Shell } from "../components/Shell";
import type { SetupPageModel } from "../models";

export interface SetupPageProps {
  readonly model: SetupPageModel;
  readonly shellUtility?: ReactNode;
}

/** One-use, JavaScript-independent administrator setup form. */
export function SetupPage({ model, shellUtility }: SetupPageProps) {
  return (
    <Shell shell={model.shell} repository={null} utility={shellUtility}>
      <main
        className="layout-width page setup-page"
        id="main-content"
        tabIndex={-1}
      >
        <header className="page-heading setup-page__heading">
          <div>
            <h1>Set up Automata</h1>
            <p>Connect the administrator account for this installation.</p>
          </div>
        </header>

        <div className="setup-page__layout">
          <section
            aria-labelledby="setup-connect-heading"
            className="panel setup-card"
          >
            <div className="panel__heading">
              <h2 id="setup-connect-heading">Connect with GitHub</h2>
              <span className="setup-card__status" role="status">
                Setup is ready
              </span>
            </div>
            <form
              action={model.form.action}
              aria-describedby="setup-form-help setup-security-note"
              autoComplete="off"
              className="setup-form"
              method="post"
            >
              <input
                name="return_path"
                type="hidden"
                value={model.form.returnPath}
              />
              <div className="setup-form__field">
                <label htmlFor="setup-bootstrap-token">Bootstrap token</label>
                <p id="setup-form-help">
                  Enter the one-time token provided by the installation operator.
                </p>
                <input
                  aria-describedby="setup-form-help setup-security-note"
                  autoCapitalize="none"
                  autoComplete="new-password"
                  autoCorrect="off"
                  id="setup-bootstrap-token"
                  name="bootstrap_token"
                  required
                  spellCheck={false}
                  type="password"
                />
              </div>
              <p className="setup-form__security" id="setup-security-note">
                The token is submitted directly to this installation and is not
                included in the page or URL.
              </p>
              <div className="setup-form__actions">
                <button className="button button--primary" type="submit">
                  Continue with GitHub
                </button>
              </div>
            </form>
          </section>

          <aside aria-labelledby="setup-guidance-heading" className="setup-guidance">
            <h2 id="setup-guidance-heading">Before you continue</h2>
            <ul>
              <li>Use the administrator identity selected by the operator.</li>
              <li>Complete the provider sign-in in this browser.</li>
              <li>Do not share or reuse the one-time token.</li>
            </ul>
          </aside>
        </div>
      </main>
    </Shell>
  );
}
