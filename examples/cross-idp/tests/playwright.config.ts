import { defineConfig } from "@playwright/test";

/**
 * Playwright config for the cross-IdP federation e2e test.
 *
 * Run prerequisites (do these by hand or in CI):
 *   docker compose up -d idp app idp-ui app-ui
 *   bash scripts/seed.sh
 *
 * Then from `examples/cross-idp/ui-app`:
 *   bunx playwright test --config=../tests/playwright.config.ts
 */
export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts$/,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://localhost:5174",
    headless: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10_000,
    ignoreHTTPSErrors: true,
  },
  reporter: [["list"]],
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
