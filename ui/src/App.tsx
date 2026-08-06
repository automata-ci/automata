import { useEffect } from "react";
import type { PageModel } from "./models";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunListPage } from "./pages/RunListPage";

export interface AppProps {
  readonly page: PageModel;
  readonly enableEnhancements?: boolean;
}

export function App({ page, enableEnhancements = false }: AppProps) {
  return (
    <>
      {page.kind === "run-list" ? (
        <RunListPage model={page} />
      ) : (
        <RunDetailPage model={page} />
      )}
      {enableEnhancements ? <ProgressiveEnhancements /> : null}
    </>
  );
}

/** Forms remain ordinary POST forms; hydration only adds a cancellation prompt. */
function ProgressiveEnhancements() {
  useEffect(() => {
    const confirmSubmission = (event: SubmitEvent) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      const message = form.dataset.confirm;
      if (message !== undefined && !window.confirm(message)) {
        event.preventDefault();
      }
    };

    document.addEventListener("submit", confirmSubmission);
    return () => document.removeEventListener("submit", confirmSubmission);
  }, []);

  return null;
}
