import type { ReactNode } from "react";
import type { SetupPageModel } from "../models";
import { useSingleSubmit } from "../hooks/useSingleSubmit";
import { SetupPageView } from "../views/SetupPageView";

export interface SetupPageProps {
  readonly model: SetupPageModel;
  readonly shellUtility?: ReactNode;
}

/** Connects the one-use form behavior to the independently rendered setup view. */
export function SetupPage({ model, shellUtility }: SetupPageProps) {
  const submission = useSingleSubmit();
  return (
    <SetupPageView
      isSubmitting={submission.isSubmitting}
      model={model}
      onSubmit={submission.onSubmit}
      shellUtility={shellUtility}
    />
  );
}
