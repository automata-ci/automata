import { useCallback, useRef, useState, type FormEventHandler } from "react";

/** Prevents duplicate native form submissions while preserving no-JavaScript behavior. */
export function useSingleSubmit() {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const submitted = useRef(false);

  const onSubmit = useCallback<FormEventHandler<HTMLFormElement>>((event) => {
    if (submitted.current) {
      event.preventDefault();
      return;
    }
    submitted.current = true;
    setIsSubmitting(true);
  }, []);

  return { isSubmitting, onSubmit } as const;
}
