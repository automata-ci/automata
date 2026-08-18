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
  parameters: { layout: "fullscreen" },
  title: "Pages/Setup",
} satisfies Meta<typeof SetupPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Ready: Story = {
  args: {
    isSubmitting: false,
    onSubmit: fn((event) => event.preventDefault()),
  },
  play: async ({ args, canvas, canvasElement, userEvent }) => {
    const token = canvas.getByLabelText("Bootstrap token");
    await userEvent.type(token, "one-time-token");
    await userEvent.click(
      canvas.getByRole("button", { name: "Continue with GitHub" }),
    );
    await expect(args.onSubmit).toHaveBeenCalledOnce();
    await userEvent.clear(token);
    token.blur();
    canvasElement.ownerDocument.defaultView?.scrollTo(0, 0);
  },
};
export const Submitting: Story = { args: { isSubmitting: true } };
