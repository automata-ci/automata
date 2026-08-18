export interface AutomataMarkProps {
  readonly className?: string;
}

/** The official Automata mark, kept decorative when paired with the wordmark. */
export function AutomataMark({ className }: AutomataMarkProps) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="currentColor"
      focusable="false"
      height="15"
      viewBox="0 0 14 9"
      width="24"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect width="4" height="4" />
      <rect x="5" width="4" height="4" />
      <rect x="10" width="4" height="4" />
      <rect x="5" y="5" width="4" height="4" />
    </svg>
  );
}
