import type { Meta, StoryObj } from "@storybook/react-vite";
import { CommitLink } from "./CommitLink";

const meta = { component: CommitLink, parameters: { layout: "centered" }, title: "Components/Source/CommitLink" } satisfies Meta<typeof CommitLink>;
export default meta;
type Story = StoryObj<typeof meta>;
export const WithMessage: Story = { args: { className: "run-name", commit: { shortSha: "082b454", message: "Polish UI styling consistency", href: "https://github.com/automata-ci/automata/commit/082b454" }, messageClassName: "run-row__context" } };
export const WithoutMessage: Story = { args: { ...WithMessage.args, commit: { shortSha: "082b454", message: null, href: "https://github.com/automata-ci/automata/commit/082b454" } } };
