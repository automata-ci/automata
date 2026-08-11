import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
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
    environment: "jsdom",
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
    restoreMocks: true,
  },
});
