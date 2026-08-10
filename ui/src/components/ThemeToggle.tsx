import { Icon } from "./Icon";
import { useThemePreference } from "./useThemePreference";

export function ThemeToggle() {
  const { chooseNextTheme, theme } = useThemePreference();
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
      onClick={chooseNextTheme}
      title={controlLabel}
      type="button"
    >
      <Icon name={resolvedTheme === "dark" ? "sun" : "moon"} />
      <span>{nextLabel}</span>
    </button>
  );
}
