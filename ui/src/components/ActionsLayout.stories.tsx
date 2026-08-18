import type { Meta, StoryObj } from "@storybook/react-vite";
import { ActionsLayout } from "./ActionsLayout";

const meta = {
  component: ActionsLayout,
  title: "Components/Layout/ActionsLayout",
} satisfies Meta<typeof ActionsLayout>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    navigation: (
      <nav aria-label="Example navigation" className="panel">
        <div className="panel__heading">
          <h2>Navigation</h2>
        </div>
        <div style={{ padding: 16 }}>
          <a
            aria-current="page"
            className="button button--quiet"
            href="#current"
          >
            Current item
          </a>
        </div>
      </nav>
    ),
    children: (
      <section className="panel">
        <div className="panel__heading">
          <h2>Actions content</h2>
        </div>
        <div style={{ display: "grid", gap: 12, padding: 16 }}>
          <p style={{ margin: 0 }}>
            Page-specific content uses the remaining width without overflowing.
          </p>
          <button
            className="button button--primary"
            style={{ justifySelf: "start" }}
            type="button"
          >
            Continue
          </button>
        </div>
      </section>
    ),
  },
};
