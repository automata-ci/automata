import type { Meta, StoryObj } from "@storybook/react-vite";
import { Icon, type IconName } from "./Icon";

const iconNames: readonly IconName[] = [
  "actions",
  "artifact",
  "branch",
  "chevron-down",
  "chevron-right",
  "commit",
  "moon",
  "organizations",
  "overview",
  "pull-request",
  "repository",
  "search",
  "settings",
  "sign-out",
  "sun",
  "tag",
  "workflow",
];

const meta = {
  component: Icon,
  parameters: { layout: "centered" },
  title: "Foundations/Icon",
} satisfies Meta<typeof Icon>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: { name: "actions", size: 20 },
};

export const Catalog: Story = {
  args: { name: "actions" },
  render: () => (
    <div
      style={{
        display: "grid",
        gap: 16,
        gridTemplateColumns: "repeat(3, 1fr)",
      }}
    >
      {iconNames.map((name) => (
        <span
          key={name}
          style={{ alignItems: "center", display: "flex", gap: 8 }}
        >
          <Icon name={name} size={20} />
          {name}
        </span>
      ))}
    </div>
  ),
};
