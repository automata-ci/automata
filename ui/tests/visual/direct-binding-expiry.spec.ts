import { expect, test } from "@playwright/test";
import {
  authorizedManagementFixtures,
  installAuthorizedManagementFixture,
} from "./authorizedManagementFixtures";

test("direct binding expiry uses the native UTC minute control", async ({ page }) => {
  const fixture = authorizedManagementFixtures.find(
    (candidate) => candidate.name === "direct-binding",
  );
  if (fixture === undefined) {
    throw new Error("The direct-binding authorized fixture is missing");
  }

  await page.goto(fixture.previewUrl, { waitUntil: "networkidle" });
  await installAuthorizedManagementFixture(page, fixture);

  const input = page.getByLabel("Valid until (UTC)");
  await expect(input).toHaveAttribute("type", "datetime-local");
  await expect(input).toHaveAttribute("step", "60");
  await expect(input).toHaveAttribute(
    "aria-describedby",
    "visual-valid-until-hint",
  );
  await expect(input).toHaveAttribute(
    "aria-labelledby",
    "visual-valid-until-label",
  );
  await expect(page.locator("#visual-valid-until-hint")).toHaveText(
    "Leave blank for no expiry.",
  );

  await input.fill("2024-02-29T12:34");
  expect(await input.evaluate((control: HTMLInputElement) => ({
    stepMismatch: control.validity.stepMismatch,
    valid: control.checkValidity(),
    value: control.value,
  }))).toEqual({
    stepMismatch: false,
    valid: true,
    value: "2024-02-29T12:34",
  });

  expect(await input.evaluate((control: HTMLInputElement) => {
    control.value = "2024-02-29T12:34:30";
    return {
      stepMismatch: control.validity.stepMismatch,
      valid: control.checkValidity(),
    };
  })).toEqual({ stepMismatch: true, valid: false });
});
