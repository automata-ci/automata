import {
  DocsContainer,
  type DocsContainerProps,
} from "@storybook/addon-docs/blocks";
import type { Decorator, Preview } from "@storybook/react-vite";
import { useEffect, useState } from "react";
import { themes } from "storybook/theming";
import "../src/styles.css";
import "./preview.css";

const withColorTheme: Decorator = (Story, context) => {
  const theme = context.globals.theme === "dark" ? "dark" : "light";

  // Apply the theme during render instead of in an effect. This keeps the
  // toolbar, CSS tokens, and first painted frame in the same state.
  document.documentElement.dataset.theme = theme;

  return <Story />;
};

function ThemedDocsContainer({ children, context }: DocsContainerProps) {
  const [selectedTheme, setSelectedTheme] = useState(
    document.documentElement.dataset.theme,
  );

  useEffect(() => {
    const root = document.documentElement;
    const syncTheme = () => setSelectedTheme(root.dataset.theme);
    const observer = new MutationObserver(syncTheme);

    syncTheme();
    observer.observe(root, { attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);

  const theme = selectedTheme === "dark" ? themes.dark : themes.light;

  return (
    <DocsContainer context={context} theme={theme}>
      {children}
    </DocsContainer>
  );
}

const preview: Preview = {
  decorators: [withColorTheme],
  globalTypes: {
    theme: {
      description: "Color theme",
      toolbar: {
        dynamicTitle: true,
        icon: "paintbrush",
        items: [
          { title: "Light", value: "light" },
          { title: "Dark", value: "dark" },
        ],
      },
    },
  },
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
    docs: {
      container: ThemedDocsContainer,
    },
    // Isolated components should have breathing room by default. Page and
    // shell stories opt into fullscreen explicitly so their real layout is
    // still exercised edge to edge.
    layout: "padded",
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
