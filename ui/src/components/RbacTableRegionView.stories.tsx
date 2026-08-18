import type { Meta, StoryObj } from "@storybook/react-vite";
import { RbacTableRegionView } from "./RbacTableRegionView";

const exampleTable = (minWidth: number) => (
  <table className="rbac-table" style={{ minWidth }}>
    <thead><tr><th>Member</th><th>Role</th><th>Scope</th></tr></thead>
    <tbody><tr><th>Ada Lovelace</th><td>Maintainer</td><td>automata-ci/automata</td></tr></tbody>
  </table>
);

const meta = {
  args: {
    children: exampleTable(320),
    labelledBy: "rbac-story-heading",
  },
  component: RbacTableRegionView,
  decorators: [(Story) => <div style={{ maxWidth: 480 }}><h2 id="rbac-story-heading">Members</h2><Story /></div>],
  title: "Components/RBAC/TableRegion",
} satisfies Meta<typeof RbacTableRegionView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Fits: Story = { args: { isOverflowing: false } };
export const Overflowing: Story = { args: { children: exampleTable(720), isOverflowing: true } };
