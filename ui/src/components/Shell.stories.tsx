import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRepository, previewShell } from "../preview/sampleData";
import { Shell } from "./Shell";

const meta = {
  args: { children: <main className="layout-width page" id="main-content"><h1>Workflow runs</h1><p>Page content is independently supplied.</p></main>, repository: previewRepository, shell: previewShell },
  component: Shell,
  title: "Components/Layout/Shell",
} satisfies Meta<typeof Shell>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Repository: Story = {};
export const TenantPage: Story = { args: { repository: null } };
export const SignedOut: Story = { args: { repository: null, shell: { ...previewShell, signOut: null, signIn: { action: "/auth/github/login", returnPath: "/repositories" }, viewer: null } } };
