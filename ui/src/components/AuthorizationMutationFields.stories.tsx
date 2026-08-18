import type { Meta, StoryObj } from "@storybook/react-vite";
import { AuthorizationMutationFields } from "./AuthorizationMutationFields";

const meta = {
  component: AuthorizationMutationFields,
  parameters: { layout: "centered" },
  title: "Components/RBAC/AuthorizationMutationFields",
} satisfies Meta<typeof AuthorizationMutationFields>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    capability: {
      csrfToken: "csrf-token",
      expectedAuthorizationRevision: "42",
    },
  },
  render: (args) => (
    <form
      className="panel"
      onSubmit={(event) => event.preventDefault()}
      style={{ width: "min(360px, calc(100vw - 32px))" }}
    >
      <div className="panel__heading">
        <h2>Authorization update</h2>
      </div>
      <div style={{ display: "grid", gap: 12, padding: 16 }}>
        <p style={{ margin: 0 }}>
          Protected mutations submit the current authorization revision and CSRF
          token as hidden fields.
        </p>
        <AuthorizationMutationFields {...args} />
        <button
          className="button button--primary"
          style={{ justifySelf: "start" }}
          type="submit"
        >
          Save access
        </button>
      </div>
    </form>
  ),
};
