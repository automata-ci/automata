import type { Meta, StoryObj } from "@storybook/react-vite";
import { SourceRefLink } from "./SourceRefLink";

const meta = {
  component: SourceRefLink,
  parameters: { layout: "centered" },
  title: "Components/Source/SourceRefLink",
} satisfies Meta<typeof SourceRefLink>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Branch: Story = {
  args: {
    refModel: {
      kind: "branch",
      name: "main",
      href: "https://github.com/automata-ci/automata/tree/main",
    },
  },
};
export const Tag: Story = {
  args: {
    refModel: {
      kind: "tag",
      name: "v1.0.0",
      href: "https://github.com/automata-ci/automata/tree/v1.0.0",
    },
  },
};
export const PullRequestRef: Story = {
  args: {
    refModel: {
      kind: "ref",
      name: "refs/pull/457/merge",
      href: "https://github.com/automata-ci/automata/pull/457",
    },
  },
};
