import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRepository, previewWorkflows } from "../preview/sampleData";
import { WorkflowNavigation } from "./WorkflowNavigation";

const meta = {
  component: WorkflowNavigation,
  parameters: { layout: "padded" },
  title: "Components/Navigation/WorkflowNavigation",
} satisfies Meta<typeof WorkflowNavigation>;
export default meta;
type Story = StoryObj<typeof meta>;
export const AllWorkflows: Story = {
  args: {
    navigation: {
      pagination: { previousHref: null, nextHref: null, label: "2 workflows" },
      selectedWorkflow: null,
      workflows: previewWorkflows,
    },
    repository: previewRepository,
  },
};
export const Selected: Story = {
  args: {
    navigation: {
      pagination: { previousHref: null, nextHref: null, label: "2 workflows" },
      selectedWorkflow: previewWorkflows[0] ?? null,
      workflows: previewWorkflows,
    },
    repository: previewRepository,
  },
};
export const Empty: Story = {
  args: { navigation: null, repository: previewRepository },
};
