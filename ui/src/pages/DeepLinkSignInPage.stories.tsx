import type { Meta, StoryObj } from "@storybook/react-vite";
import type { DeepLinkSignInPageModel } from "../models";
import { previewShell } from "../preview/sampleData";
import { DeepLinkSignInPage } from "./DeepLinkSignInPage";

const model: DeepLinkSignInPageModel = {
  kind: "deep-link-sign-in",
  shell: {
    ...previewShell,
    documentTitle: "Sign in · Automata",
    signOut: null,
    viewer: null,
    signIn: {
      action: "/auth/github/login",
      returnPath: "/automata-ci/automata/actions/runs/42/jobs/test",
    },
  },
};
const meta = {
  component: DeepLinkSignInPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Sign In",
} satisfies Meta<typeof DeepLinkSignInPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Default: Story = { args: { model } };
