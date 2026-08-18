import { Icon } from "./Icon";

export interface ThemeToggleViewProps {
  readonly onToggle: () => void;
  readonly theme: "light" | "dark" | null;
}

/** Pure color-theme control; preference persistence lives in its container hook. */
export function ThemeToggleView({ onToggle, theme }: ThemeToggleViewProps) {
  const resolvedTheme = theme ?? "light";
  const nextTheme = resolvedTheme === "dark" ? "light" : "dark";
  const nextLabel = theme === null
    ? "Theme"
    : nextTheme === "dark"
      ? "Dark"
      : "Light";
  const controlLabel = theme === null ? "Color theme" : `Use ${nextTheme} theme`;

  return (
    <button
      aria-label={controlLabel}
      className="theme-toggle"
      disabled={theme === null}
      onClick={onToggle}
      title={controlLabel}
      type="button"
    >
      <Icon name={resolvedTheme === "dark" ? "sun" : "moon"} />
      <span>{nextLabel}</span>
    </button>
  );
}
