import react from "@vitejs/plugin-react";
import { storybookTest } from "@storybook/addon-vitest/vitest-plugin";
import { playwright } from "@vitest/browser-playwright";
import { defineConfig, defineProject } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.stories.{ts,tsx}"],
      reporter: ["text", "json-summary", "lcov", "html"],
      reportsDirectory: "coverage",
      reportOnFailure: true,
      thresholds: {
        branches: 84,
        functions: 96,
        lines: 93,
        statements: 93,
      },
    },
    projects: [
      defineProject({
        extends: true,
        test: {
          name: "unit",
          environment: "jsdom",
          include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
          restoreMocks: true,
        },
      }),
      defineProject({
        extends: true,
        optimizeDeps: {
          include: ["storybook/theming"],
        },
        plugins: [
          storybookTest({
            configDir: ".storybook",
            storybookScript: "npm run storybook",
          }),
        ],
        test: {
          name: "storybook",
          browser: {
            enabled: true,
            headless: true,
            instances: [{ browser: "chromium" }],
            provider: playwright({}),
          },
          isolate: false,
        },
      }),
    ],
  },
});
