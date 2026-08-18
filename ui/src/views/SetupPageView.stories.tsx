import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import type { SetupPageModel } from "../models";
import { previewShell } from "../preview/sampleData";
import { SetupPageView } from "./SetupPageView";

const model: SetupPageModel = {
  kind: "setup",
  shell: {
    ...previewShell,
    documentTitle: "Set up Automata",
    navigation: [],
    signOut: null,
    viewer: null,
  },
  form: {
    action: "/setup/auth/github",
    returnPath: "/",
  },
};

const meta = {
  args: { model, onSubmit: fn() },
  component: SetupPageView,
  title: "Pages/Setup",
} satisfies Meta<typeof SetupPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Ready: Story = { args: { isSubmitting: false } };
export const Submitting: Story = { args: { isSubmitting: true } };
