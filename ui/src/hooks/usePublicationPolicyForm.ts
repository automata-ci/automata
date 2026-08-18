import { useCallback, useEffect, useRef, useState, type FormEventHandler } from "react";
import type {
  PublicationAudience,
  RepositoryPublicationPolicyModel,
} from "../models";
import type { PublicationPolicyFormState } from "../viewModels/publicationPolicy";

const policyFields: readonly (keyof RepositoryPublicationPolicyModel)[] = [
  "dashboard",
  "logs",
  "artifacts",
];

/** Owns enhanced policy-draft behavior while retaining a native POST fallback. */
export function usePublicationPolicyForm(
  policy: RepositoryPublicationPolicyModel,
): PublicationPolicyFormState {
  const [draftPolicy, setDraftPolicy] = useState(policy);
  const [clientReady, setClientReady] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const submitted = useRef(false);
  const hasChanges = policyFields.some(
    (field) => draftPolicy[field] !== policy[field],
  );

  useEffect(() => {
    setClientReady(true);
    const restoreAfterHistoryNavigation = (event: PageTransitionEvent) => {
      if (!event.persisted) return;
      if (submitted.current) {
        submitted.current = false;
        window.history.go(0);
      } else {
        setIsSubmitting(false);
      }
    };
    window.addEventListener("pageshow", restoreAfterHistoryNavigation);
    return () => window.removeEventListener("pageshow", restoreAfterHistoryNavigation);
  }, []);

  const onChange = useCallback((
    field: keyof RepositoryPublicationPolicyModel,
    value: PublicationAudience,
  ) => {
    setDraftPolicy((current) => ({ ...current, [field]: value }));
  }, []);

  const onSubmit = useCallback<FormEventHandler<HTMLFormElement>>((event) => {
    if (clientReady && !hasChanges) {
      event.preventDefault();
      return;
    }
    if (clientReady) {
      submitted.current = true;
      setIsSubmitting(true);
    }
  }, [clientReady, hasChanges]);

  return {
    draftPolicy,
    isSubmitting,
    onChange,
    onSubmit,
    saveDisabled: clientReady && (!hasChanges || isSubmitting),
  };
}
