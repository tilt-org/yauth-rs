import { expect, test } from "@playwright/test";

const APP_UI = process.env.APP_UI ?? "http://localhost:5174";
const IDP_UI = process.env.IDP_UI ?? "http://localhost:5173";

test("federated login: App → IdP → consent → App dashboard", async ({
  page,
}) => {
  // 1. Land on the App.
  await page.goto(APP_UI);
  await expect(page.getByText("Server B")).toBeVisible();

  // 2. Kick off the SSO flow.
  const ssoLink = page.getByRole("link", { name: /Sign in via Server A/i });
  await expect(ssoLink).toBeVisible();
  await ssoLink.click();

  // 3. The browser should land on the IdP UI's login page.
  await page.waitForURL((url) => url.origin === IDP_UI, { timeout: 30_000 });
  await expect(page.getByText("Sign in to Server A")).toBeVisible();

  // 4. Fill in alice's credentials.
  await page.getByPlaceholder(/email/i).fill("alice@example.com");
  await page.getByPlaceholder(/password/i).fill("alicepasswd1");
  await page.getByRole("button", { name: /sign in|log in/i }).click();

  // 5. Consent screen → approve.
  await expect(page.getByText(/Authorize Server B/i)).toBeVisible({
    timeout: 15_000,
  });
  await page.getByRole("button", { name: /allow/i }).click();

  // 6. Should bounce back to the App and land on /dashboard.
  await page.waitForURL((url) => url.origin === APP_UI, { timeout: 30_000 });
  await expect(page.getByText(/Signed in \(federated\)/i)).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText("alice@example.com")).toBeVisible();
});
