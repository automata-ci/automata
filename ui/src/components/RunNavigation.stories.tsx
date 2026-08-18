import type { Meta, StoryObj } from "@storybook/react-vite";
import { RunNavigation } from "./RunNavigation";

const jobs = [
  { id: "build", href: "/runs/42/jobs/build", name: "Build", status: { label: "Succeeded", tone: "success" as const } },
  { id: "test", href: "/runs/42/jobs/test", name: "Test on Linux", status: { label: "In progress", tone: "running" as const } },
  { id: "release", href: null, name: "Release", status: { label: "Queued", tone: "queued" as const } },
];
const meta = { component: RunNavigation, parameters: { layout: "padded" }, title: "Components/Navigation/RunNavigation" } satisfies Meta<typeof RunNavigation>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Summary: Story = { args: { jobs, jobsVisibility: "full", pagination: null, selectedJobId: null, summaryHref: null } };
export const SelectedJob: Story = { args: { ...Summary.args, selectedJobId: "test", summaryHref: "/runs/42" } };
export const Restricted: Story = { args: { jobs: [], jobsVisibility: "restricted", pagination: null, selectedJobId: null, summaryHref: "/runs/42" } };
