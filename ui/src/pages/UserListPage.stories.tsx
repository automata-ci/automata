import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewUserList } from "../preview/rbacModels";
import { UserListPage } from "./UserListPage";

const model = previewUserList();
const meta = { component: UserListPage, title: "Pages/Access/Members" } satisfies Meta<typeof UserListPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Populated: Story = { args: { model } };
export const Empty: Story = { args: { model: { ...model, users: [] } } };
