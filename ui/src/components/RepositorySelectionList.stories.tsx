import type { Meta, StoryObj } from "@storybook/react-vite";
import { RepositorySelectionList } from "./RepositorySelectionList";

const repositories = [{ defaultBranch: "main", id: "1", name: "automata", owner: "automata-ci", private: false, selected: true }, { defaultBranch: "main", id: "2", name: "infra", owner: "automata-ci", private: true, selected: false }];
const meta = { component: RepositorySelectionList, parameters: { layout: "padded" }, title: "Components/Providers/RepositorySelectionList" } satisfies Meta<typeof RepositorySelectionList>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Populated: Story = { args: { repositories } };
export const Disabled: Story = { args: { disabled: true, repositories } };
export const Empty: Story = { args: { repositories: [] } };
