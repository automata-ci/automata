import type { Meta, StoryObj } from "@storybook/react-vite";
import { RbacTableRegionView } from "./RbacTableRegionView";

const exampleTable = (wide = false) => (
  <table className={`rbac-table${wide ? " rbac-table--bindings" : ""}`}>
    <thead>
      <tr>
        <th>Member</th>
        <th>Role</th>
        <th>Scope</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <th>Ada Lovelace</th>
        <td data-label="Role">Maintainer</td>
        <td data-label="Scope">automata-ci/automata</td>
      </tr>
    </tbody>
  </table>
);

const meta = {
  args: {
    children: exampleTable(),
    labelledBy: "rbac-story-heading",
  },
  component: RbacTableRegionView,
  decorators: [
    (Story) => (
      <div className="rbac-management__content" style={{ maxWidth: 720 }}>
        <h2 id="rbac-story-heading">Members</h2>
        <Story />
      </div>
    ),
  ],
  title: "Components/RBAC/TableRegion",
} satisfies Meta<typeof RbacTableRegionView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Fits: Story = { args: { isOverflowing: false } };
export const Overflowing: Story = {
  args: { children: exampleTable(true), isOverflowing: true },
};
