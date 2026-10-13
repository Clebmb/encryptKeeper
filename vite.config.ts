import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // Keep Vite's watcher off the Rust build output; Cargo rewrites those
      // files mid-build and Windows reports EBUSY when Vite tries to watch them.
      ignored: ["**/src-tauri/**"],
    },
  },
  clearScreen: false,
});
