import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [react()],
  publicDir: false,
  build: {
    copyPublicDir: false,
    emptyOutDir: true,
    outDir: "dist/preview",
    target: "es2022",
  },
});
