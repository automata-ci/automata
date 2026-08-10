import { defineConfig } from "@playwright/test";

const previewOrigin = "http://127.0.0.1:4173";
const previewBasePath = "/automata/";
const previewBaseUrl = `${previewOrigin}${previewBasePath}`;

export default defineConfig({
  testDir: "tests/visual",
  outputDir: "dist/playwright",
  forbidOnly: process.env.CI !== undefined,
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: previewBaseUrl,
    browserName: "chromium",
    headless: true,
    locale: "en-US",
    reducedMotion: "reduce",
    timezoneId: "UTC",
    viewport: { width: 1440, height: 1000 },
  },
  webServer: {
    command:
      `npm run preview:site -- --host 127.0.0.1 --port 4173 --strictPort ` +
      `--base ${previewBasePath}`,
    reuseExistingServer: false,
    timeout: 30_000,
    url: previewBaseUrl,
  },
});
