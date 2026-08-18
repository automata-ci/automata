import { withThemeByDataAttribute } from "@storybook/addon-themes";
import type { Preview, Renderer } from "@storybook/react-vite";
import "../src/styles.css";

const preview: Preview = {
  decorators: [
    withThemeByDataAttribute<Renderer>({
      themes: {
        light: "light",
        dark: "dark",
      },
      defaultTheme: "light",
      attributeName: "data-theme",
    }),
  ],
  initialGlobals: {
    theme: "light",
  },
  parameters: {
    a11y: {
      test: "error",
    },
    controls: {
      expanded: true,
    },
    layout: "fullscreen",
    options: {
      storySort: {
        order: ["Foundations", "Components", "Features", "Pages"],
      },
    },
    viewport: {
      options: {
        desktop: {
          name: "Desktop",
          styles: { width: "1440px", height: "1000px" },
          type: "desktop",
        },
        tablet: {
          name: "Tablet",
          styles: { width: "768px", height: "1024px" },
          type: "tablet",
        },
        mobile: {
          name: "Mobile",
          styles: { width: "390px", height: "844px" },
          type: "mobile",
        },
      },
    },
  },
  tags: ["autodocs", "test"],
};

export default preview;
