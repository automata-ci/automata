import type { FormEventHandler } from "react";
import type {
  PublicationAudience,
  RepositoryPublicationPolicyModel,
} from "../models";

export interface PublicationPolicyFormState {
  readonly draftPolicy: RepositoryPublicationPolicyModel;
  readonly isSubmitting: boolean;
  readonly onChange: (
    field: keyof RepositoryPublicationPolicyModel,
    value: PublicationAudience,
  ) => void;
  readonly onSubmit: FormEventHandler<HTMLFormElement>;
  readonly saveDisabled: boolean;
}
