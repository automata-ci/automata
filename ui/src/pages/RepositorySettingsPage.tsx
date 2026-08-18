import type { ReactNode } from "react";
import type { RepositorySettingsPageModel } from "../models";
import { usePublicationPolicyForm } from "../hooks/usePublicationPolicyForm";
import { RepositorySettingsPageView } from "../views/RepositorySettingsPageView";

export interface RepositorySettingsPageProps {
  readonly model: RepositorySettingsPageModel;
  readonly shellUtility?: ReactNode;
}

/** Connects publication-policy draft behavior to a pure settings view. */
export function RepositorySettingsPage({
  model,
  shellUtility,
}: RepositorySettingsPageProps) {
  const form = usePublicationPolicyForm(model.policy);
  return (
    <RepositorySettingsPageView
      form={form}
      model={model}
      shellUtility={shellUtility}
    />
  );
}
