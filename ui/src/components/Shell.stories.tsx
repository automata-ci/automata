import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, userEvent, within } from "storybook/test";
import { previewRepository, previewShell } from "../preview/sampleData";
import { Shell } from "./Shell";

const meta = {
  args: {
    children: (
      <main className="layout-width page" id="main-content">
        <h1>Workflow runs</h1>
        <p>Page content is independently supplied.</p>
      </main>
    ),
    repository: previewRepository,
    shell: previewShell,
  },
  component: Shell,
  parameters: { layout: "fullscreen" },
  title: "Components/Layout/Shell",
} satisfies Meta<typeof Shell>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Repository: Story = {};
export const TenantPage: Story = { args: { repository: null } };
export const AccountMenu: Story = {
  args: {
    repository: null,
    shell: {
      ...previewShell,
      accountNavigation: [
        {
          icon: "organizations",
          label: "Organizations",
          href: "/organizations",
        },
        { icon: "settings", label: "Settings", href: "/settings" },
      ],
      signOut: {
        action: "/auth/logout",
        csrfToken: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      },
      viewer: { displayName: "Ada Lovelace’s Analytical Engine" },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByText(/account menu$/u));
    await expect(
      canvas.getByRole("navigation", { name: "Account navigation" }),
    ).toBeVisible();
    await expect(canvas.getByRole("link", { name: "Organizations" })).toBeVisible();
    await expect(canvas.getByRole("link", { name: "Settings" })).toBeVisible();
    await expect(canvas.getByRole("button", { name: "Sign out" })).toBeVisible();
    await expect(canvas.getByTitle("Ada Lovelace’s Analytical Engine")).toBeVisible();
  },
};
export const SignedOut: Story = {
  args: {
    repository: null,
    shell: {
      ...previewShell,
      signOut: null,
      signIn: { action: "/auth/github/login", returnPath: "/repositories" },
      viewer: null,
    },
  },
};
