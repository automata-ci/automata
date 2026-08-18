import type { Meta, StoryObj } from "@storybook/react-vite";
import { AuthorizationMutationFields } from "./AuthorizationMutationFields";

const meta = { component: AuthorizationMutationFields, parameters: { layout: "centered" }, title: "Components/RBAC/AuthorizationMutationFields" } satisfies Meta<typeof AuthorizationMutationFields>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Default: Story = { args: { capability: { csrfToken: "csrf-token", expectedAuthorizationRevision: "42" } }, render: (args) => <form><AuthorizationMutationFields {...args} /><button className="button" type="submit">Save access</button></form> };
