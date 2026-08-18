import type { Meta, StoryObj } from "@storybook/react-vite";
import { RepositorySettingsNavigation } from "./RepositorySettingsNavigation";

const meta = { component: RepositorySettingsNavigation, parameters: { layout: "padded" }, title: "Components/Navigation/RepositorySettingsNavigation" } satisfies Meta<typeof RepositorySettingsNavigation>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Access: Story = { args: { navigation: { accessHref: "?view=settings", secretsHref: "?view=secrets", current: "access" } } };
export const Secrets: Story = { args: { navigation: { ...Access.args.navigation, current: "secrets" } } };
