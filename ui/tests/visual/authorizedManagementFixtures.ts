import type { Page } from "@playwright/test";

export interface AuthorizedManagementFixture {
  readonly markup: string;
  readonly name: string;
  readonly placement: "before" | "replace";
  readonly previewUrl: string;
  readonly targetSelector: string;
}

/**
 * Test-only visual states for CSS/layout coverage. SSR integration tests own
 * the exact production form fields; the public preview remains capability-free.
 */
export const authorizedManagementFixtures: readonly AuthorizedManagementFixture[] = [
  {
    name: "repository-settings",
    previewUrl: "./?view=settings",
    targetSelector: ".repository-settings > div:last-child",
    placement: "replace",
    markup: `
      <form action="/settings/access" method="post">
        <div class="repository-settings__resources">
          ${audienceFieldset("Run pages", "dashboard_audience", "public")}
          ${audienceFieldset("Job logs", "log_audience", "authenticated")}
          ${audienceFieldset("Artifacts", "artifact_audience", "private")}
        </div>
        <div class="repository-settings__actions">
          <button class="button button--primary repository-settings__save" type="submit">
            Save changes
          </button>
        </div>
      </form>
    `,
  },
  {
    name: "repository-secret-create",
    previewUrl: "./?view=secrets",
    targetSelector: ".repository-secret-read-only",
    placement: "replace",
    markup: `
      <section class="panel repository-secret-create" aria-labelledby="visual-create-secret-heading">
        <div class="panel__heading">
          <h2 id="visual-create-secret-heading">Create secret</h2>
        </div>
        <form action="#" method="post">
          <div class="repository-secret-form-grid">
            <label>
              <span>Name</span>
              <input autocomplete="off" name="name" required type="text">
              <small>Uppercase letters, digits, and underscores.</small>
            </label>
            <label>
              <span>Value</span>
              <input autocomplete="new-password" maxlength="65536" name="value" required type="password">
              <small>Maximum 64 KiB. The value is never returned to your browser.</small>
            </label>
          </div>
          <div class="repository-secret-form-actions">
            <p>The value is accepted once and cannot be retrieved from this page.</p>
            <button class="button button--primary" type="button">Create secret</button>
          </div>
        </form>
      </section>
    `,
  },
  {
    name: "repository-secret-manage",
    previewUrl: "./?view=secrets",
    targetSelector: ".repository-secret-row",
    placement: "replace",
    markup: `
      <li class="repository-secret-row">
        <div class="repository-secret-row__summary">
          <div class="repository-secret-row__identity">
            <strong>DEPLOY_TOKEN</strong>
            <span class="repository-secret-state repository-secret-state--active">Active</span>
          </div>
        </div>
        <details class="repository-secret-row__manage" open>
          <summary>Manage</summary>
          <div class="repository-secret-row__controls">
            <form action="#" method="post">
              <label>
                <span>Value</span>
                <input autocomplete="new-password" maxlength="65536" name="value" required type="password">
                <small>Maximum 64 KiB. The value is never returned to your browser.</small>
              </label>
              <button class="button button--primary" type="button">Replace value</button>
            </form>
            <form action="#" class="repository-secret-delete" method="post">
              <p>
                This revokes access immediately and schedules retained encrypted versions for deletion.
              </p>
              <button class="button repository-secret-delete__button" type="button">
                Delete secret
              </button>
            </form>
          </div>
        </details>
      </li>
    `,
  },
  {
    name: "user-status",
    previewUrl: "./?view=user&user=ada-lovelace",
    targetSelector: ".rbac-read-only",
    placement: "replace",
    markup: `
      <form action="/settings/access/users/test/status" class="rbac-native-form" method="post">
        <label>
          Reason for disabling
          <input maxlength="1024" name="reason" required>
        </label>
        <button class="button button--danger" type="submit">Disable user</button>
      </form>
    `,
  },
  {
    name: "role-create",
    previewUrl: "./?view=roles",
    targetSelector: ".rbac-panel",
    placement: "before",
    markup: `
      <section class="panel rbac-panel" aria-labelledby="visual-create-role-heading">
        <div class="panel__heading">
          <h2 id="visual-create-role-heading">Create custom role</h2>
        </div>
        <form action="/settings/access/roles" class="rbac-native-form" method="post">
          <label>Policy name<input name="name" required></label>
          <label>Display name<input name="display_name" required></label>
          <button class="button" type="submit">Create role</button>
        </form>
      </section>
    `,
  },
  {
    name: "direct-binding",
    previewUrl: "./?view=bindings",
    targetSelector: ".rbac-panel",
    placement: "before",
    markup: `
      <section class="panel rbac-panel" aria-labelledby="visual-grant-binding-heading">
        <div class="panel__heading">
          <h2 id="visual-grant-binding-heading">Grant direct role</h2>
        </div>
        <form action="/settings/access/direct-bindings" class="rbac-native-form" method="post">
          <label>User<select name="principal_id"><option>Ada Lovelace</option></select></label>
          <label>Role<select name="role_id"><option>Release reviewer</option></select></label>
          <label>Scope<select name="scope"><option>Production tenant</option></select></label>
          <label>
            <span id="visual-valid-until-label">Valid until (UTC)</span>
            <small id="visual-valid-until-hint">Leave blank for no expiry.</small>
            <input aria-describedby="visual-valid-until-hint" aria-labelledby="visual-valid-until-label" name="valid_until" step="60" type="datetime-local">
          </label>
          <button class="button" type="submit">Grant role</button>
        </form>
      </section>
    `,
  },
];

export async function installAuthorizedManagementFixture(
  page: Page,
  fixture: AuthorizedManagementFixture,
): Promise<void> {
  await page.locator(fixture.targetSelector).first().evaluate(
    (target, { markup, placement }) => {
      const template = document.createElement("template");
      template.innerHTML = markup;
      const content = template.content;
      if (placement === "replace") {
        target.replaceWith(content);
      } else {
        target.before(content);
      }
    },
    fixture,
  );
}

function audienceFieldset(
  label: string,
  name: string,
  selected: "authenticated" | "private" | "public",
): string {
  const options = [
    ["private", "Private", "Only users with repository permission can access it."],
    ["authenticated", "Signed-in users", "Anyone signed in to this tenant can access it."],
    ["public", "Public", "Anyone can access it without signing in."],
  ] as const;
  return `
    <fieldset class="audience-setting">
      <legend>${label}</legend>
      <p>Choose the default access for ${label.toLowerCase()}.</p>
      <div class="audience-options">
        ${options.map(([value, optionLabel, description]) => `
          <label class="audience-option">
            <input name="${name}" type="radio" value="${value}" ${
              value === selected ? "checked" : ""
            }>
            <span><strong>${optionLabel}</strong><small>${description}</small></span>
          </label>
        `).join("")}
      </div>
    </fieldset>
  `;
}
