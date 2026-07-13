import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8787", "/og": "http://localhost:8787" } },
  build: { outDir: "dist" },
});
