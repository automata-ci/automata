import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
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
  title: "Pages/Repository Settings",
} satisfies Meta<typeof RepositorySettingsPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const ReadOnly: Story = {};
export const Editable: Story = { args: { model: editableModel } };
export const Saving: Story = { args: { form: { ...form, isSubmitting: true, saveDisabled: true }, model: editableModel } };
