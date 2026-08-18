import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRepositoryDirectory } from "../preview/models";
import { RepositoryDirectoryPage } from "./RepositoryDirectoryPage";

const meta = { component: RepositoryDirectoryPage, title: "Pages/Repositories" } satisfies Meta<typeof RepositoryDirectoryPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Populated: Story = { args: { model: previewRepositoryDirectory(false) } };
export const Empty: Story = { args: { model: previewRepositoryDirectory(true) } };
