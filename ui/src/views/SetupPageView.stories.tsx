import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn } from "storybook/test";
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

export const Ready: Story = {
  args: {
    isSubmitting: false,
    onSubmit: fn((event) => event.preventDefault()),
  },
  play: async ({ args, canvas, userEvent }) => {
    await userEvent.type(canvas.getByLabelText("Bootstrap token"), "one-time-token");
    await userEvent.click(canvas.getByRole("button", { name: "Continue with GitHub" }));
    await expect(args.onSubmit).toHaveBeenCalledOnce();
  },
};
export const Submitting: Story = { args: { isSubmitting: true } };
