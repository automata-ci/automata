import type { Meta, StoryObj } from "@storybook/react-vite";
import { Pagination } from "./Pagination";

const meta = {
  component: Pagination,
  parameters: { layout: "centered" },
  title: "Components/Navigation/Pagination",
} satisfies Meta<typeof Pagination>;
export default meta;
type Story = StoryObj<typeof meta>;
export const MiddlePage: Story = {
  args: {
    label: "Workflow pages",
    pagination: {
      previousHref: "?before=one",
      nextHref: "?after=three",
      label: "Workflows 21–40",
    },
  },
};
export const FirstPage: Story = {
  args: {
    label: "Workflow pages",
    pagination: {
      previousHref: null,
      nextHref: "?after=two",
      label: "Workflows 1–20",
    },
  },
};
