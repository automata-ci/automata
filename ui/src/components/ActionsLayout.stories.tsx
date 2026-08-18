import type { Meta, StoryObj } from "@storybook/react-vite";
import { ActionsLayout } from "./ActionsLayout";

const meta = { component: ActionsLayout, title: "Components/Layout/ActionsLayout" } satisfies Meta<typeof ActionsLayout>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Default: Story = { args: { navigation: <nav className="panel" style={{ padding: 16 }}>Navigation</nav>, children: <section className="panel" style={{ padding: 24 }}>Actions content</section> } };
