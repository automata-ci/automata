import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn } from "storybook/test";
import type { PublicationPolicyFormState } from "../viewModels/publicationPolicy";
import { previewRepositorySettings } from "../preview/models";
import { RepositorySettingsPageView } from "./RepositorySettingsPageView";

const readOnlyModel = previewRepositorySettings();
const editableModel = {
  ...readOnlyModel,
  update: { action: "/settings/access", csrfToken: "storybook-csrf-token" },
};
const form: PublicationPolicyFormState = {
  draftPolicy: readOnlyModel.policy,
  isSubmitting: false,
  onChange: fn(),
  onSubmit: fn(),
  saveDisabled: false,
};

const meta = {
  args: { form, model: readOnlyModel },
  component: RepositorySettingsPageView,
  parameters: { layout: "fullscreen" },
  title: "Pages/Repository Settings",
} satisfies Meta<typeof RepositorySettingsPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const ReadOnly: Story = {};
export const Editable: Story = {
  args: {
    form: { ...form, onChange: fn() },
    model: editableModel,
  },
  play: async ({ args, canvas, userEvent }) => {
    const publicOptions = canvas.getAllByRole("radio", { name: /Public/ });
    const jobLogsPublic = publicOptions[1];
    if (jobLogsPublic === undefined)
      throw new Error("public audience option is missing");
    await userEvent.click(jobLogsPublic);
    await expect(args.form.onChange).toHaveBeenCalledWith("logs", "public");
  },
};
export const Saving: Story = {
  args: {
    form: { ...form, isSubmitting: true, saveDisabled: true },
    model: editableModel,
  },
};
