import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRepositorySecrets } from "../preview/models";
import { RepositorySecretsPage } from "./RepositorySecretsPage";

const model = previewRepositorySecrets();
const meta = {
  component: RepositorySecretsPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Repository Secrets",
} satisfies Meta<typeof RepositorySecretsPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const ReadOnly: Story = { args: { model } };
export const Empty: Story = { args: { model: { ...model, secrets: [] } } };
