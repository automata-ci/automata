import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewDirectBindings } from "../preview/rbacModels";
import { DirectBindingPage } from "./DirectBindingPage";

const model = previewDirectBindings();
const meta = { component: DirectBindingPage, title: "Pages/Access/Direct Bindings" } satisfies Meta<typeof DirectBindingPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const ReadOnly: Story = { args: { model } };
export const Empty: Story = { args: { model: { ...model, bindings: [] } } };
