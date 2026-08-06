import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig(({ isSsrBuild }) => ({
  plugins: [react()],
  publicDir: false,
  build: isSsrBuild
    ? {
        copyPublicDir: false,
        emptyOutDir: false,
        minify: true,
        outDir: "dist/ssr",
        rollupOptions: {
          output: {
            entryFileNames: "renderer.mjs",
            format: "es",
          },
        },
        ssr: "src/entry-server.tsx",
        target: "es2022",
      }
    : {
        copyPublicDir: false,
        emptyOutDir: false,
        manifest: "manifest.json",
        outDir: "dist/client",
        rollupOptions: {
          input: "src/entry-client.tsx",
          output: {
            assetFileNames: "assets/[name]-[hash][extname]",
            chunkFileNames: "assets/[name]-[hash].js",
            entryFileNames: "assets/[name]-[hash].js",
          },
        },
        target: "es2022",
      },
  ssr: {
    noExternal: true,
    target: "webworker",
  },
}));
