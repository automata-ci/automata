/**
 * Native GET submission replaces an action's query string. The static demo
 * stores its route in that query, so it needs this small preview-only adapter.
 * Production forms remain ordinary server-routed GET forms.
 */
export function installPreviewFormRouting(root: HTMLElement): () => void {
  const handleSubmit = (event: Event) => {
    if (
      !(event instanceof SubmitEvent) ||
      !(event.target instanceof HTMLFormElement)
    ) {
      return;
    }

    const destination = previewGetDestination(
      event.target,
      window.location.href,
      event.submitter,
    );
    if (destination === null) {
      return;
    }

    event.preventDefault();
    window.location.assign(destination);
  };

  root.addEventListener("submit", handleSubmit);
  return () => root.removeEventListener("submit", handleSubmit);
}

export function previewGetDestination(
  form: HTMLFormElement,
  currentHref: string,
  submitter: HTMLElement | null = null,
): string | null {
  const submissionControl = getSubmissionControl(form, submitter);
  if (submitter !== null && submissionControl === null) {
    return null;
  }

  const methodOverride = submissionControl?.getAttribute("formmethod");
  const method =
    methodOverride === null || methodOverride === undefined
      ? form.method.toLowerCase()
      : normalizeMethodOverride(methodOverride);
  if (method !== "get") {
    return null;
  }

  try {
    const current = new URL(currentHref);
    const actionOverride = submissionControl?.getAttribute("formaction");
    const action =
      actionOverride === null || actionOverride === undefined
        ? form.action
        : actionOverride;
    const destination = new URL(action, current);
    if (
      destination.origin !== current.origin ||
      destination.pathname !== current.pathname
    ) {
      return null;
    }

    const submitted = new FormData(form, submissionControl);
    const submittedNames = new Set<string>();
    for (const name of submitted.keys()) {
      submittedNames.add(name);
    }
    for (const name of submittedNames) {
      destination.searchParams.delete(name);
    }
    for (const [name, value] of submitted.entries()) {
      if (typeof value !== "string") {
        return null;
      }
      destination.searchParams.append(name, value);
    }

    return `${destination.pathname}${destination.search}${destination.hash}`;
  } catch {
    return null;
  }
}

function getSubmissionControl(
  form: HTMLFormElement,
  submitter: HTMLElement | null,
): HTMLButtonElement | HTMLInputElement | null {
  if (submitter === null) {
    return null;
  }
  if (
    submitter instanceof HTMLButtonElement &&
    submitter.type === "submit" &&
    submitter.form === form
  ) {
    return submitter;
  }
  if (
    submitter instanceof HTMLInputElement &&
    (submitter.type === "submit" || submitter.type === "image") &&
    submitter.form === form
  ) {
    return submitter;
  }
  return null;
}

function normalizeMethodOverride(value: string): string {
  const method = value.toLowerCase();
  return method === "post" || method === "dialog" ? method : "get";
}
