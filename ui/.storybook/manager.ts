import { GLOBALS_UPDATED } from "storybook/internal/core-events";
import type { GlobalsUpdatedPayload } from "storybook/internal/types";
import { addons } from "storybook/manager-api";
import { themes } from "storybook/theming";

const managerTheme = (theme: unknown) =>
  theme === "dark" ? themes.dark : themes.light;

addons.register("automata/color-theme", (api) => {
  let activeTheme: unknown;

  const applyTheme = (theme: unknown) => {
    if (theme === activeTheme) return;

    activeTheme = theme;
    addons.setConfig({ theme: managerTheme(theme) });
  };

  applyTheme(api.getGlobals().theme);
  api.on(GLOBALS_UPDATED, ({ globals }: GlobalsUpdatedPayload) => {
    applyTheme(globals.theme);
  });
});
