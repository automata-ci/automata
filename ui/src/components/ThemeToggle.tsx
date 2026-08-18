import { useThemePreference } from "../hooks/useThemePreference";
import { ThemeToggleView } from "./ThemeToggleView";

export function ThemeToggle() {
  const { chooseNextTheme, theme } = useThemePreference();
  return <ThemeToggleView onToggle={chooseNextTheme} theme={theme} />;
}
