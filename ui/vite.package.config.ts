import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    copyPublicDir: false,
    emptyOutDir: true,
    lib: {
      entry: "src/public.ts",
      fileName: "index",
      formats: ["es"],
    },
    minify: true,
    outDir: "dist/package",
    rollupOptions: {
      external: (id) => id === "react" || id.startsWith("react/"),
    },
    target: "es2022",
  },
});
