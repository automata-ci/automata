import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import { RunPriorityControlsView } from "./RunPriorityControlsView";

const meta = {
  title: "Views/Run priority controls",
  component: RunPriorityControlsView,
  args: {
    current: 50,
    csrfToken: "storybook-csrf-token",
    endpoint: "/automata-ci/automata/actions/runs/run-1/priority",
    error: null,
    onChange: fn(),
    onSubmit: fn(),
    pending: false,
  },
} satisfies Meta<typeof RunPriorityControlsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};

export const Pending: Story = {
  args: { pending: true },
};

export const Error: Story = {
  args: { error: "The priority could not be updated. Refresh and try again." },
};
