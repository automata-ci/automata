import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewUserDetail } from "../preview/rbacModels";
import { UserDetailPage } from "./UserDetailPage";

const model = previewUserDetail();
if (model === null) throw new Error("member preview fixture is unavailable");
const meta = { component: UserDetailPage, title: "Pages/Access/Member Detail" } satisfies Meta<typeof UserDetailPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Active: Story = { args: { model } };
export const Disabled: Story = { args: { model: previewUserDetail("grace-hopper") ?? model } };
