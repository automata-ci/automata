import type { ReactNode } from "react";
import type { DeepLinkSignInPageModel } from "../models";
import { Shell } from "../components/Shell";

export interface DeepLinkSignInPageProps {
  readonly model: DeepLinkSignInPageModel;
  readonly shellUtility?: ReactNode;
}

export function DeepLinkSignInPage({
  model,
  shellUtility,
}: DeepLinkSignInPageProps) {
  return (
    <Shell shell={model.shell} repository={null} utility={shellUtility}>
      <main className="layout-width page" id="main-content" tabIndex={-1}>
        <section className="panel empty-state" aria-labelledby="sign-in-heading">
          <h1 id="sign-in-heading">Sign in to view this run</h1>
          <p>
            This run may require authentication. Sign in and Automata will
            return you to this exact job.
          </p>
          {model.shell.signIn === null ? null : (
            <form action={model.shell.signIn.action} method="post">
              <input
                name="return_path"
                type="hidden"
                value={model.shell.signIn.returnPath}
              />
              <button className="button button--primary" type="submit">
                Sign in with GitHub
              </button>
            </form>
          )}
        </section>
      </main>
    </Shell>
  );
}
