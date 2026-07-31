import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// The dev server proxies the API to a locally running havuz, so `pnpm dev`
// needs no CORS configuration and no separate build of the Rust side.
const ADMIN = process.env.HAVUZ_ADMIN_URL ?? "http://127.0.0.1:7432";

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The binary embeds these, so a smaller bundle is a smaller havuz.
    target: "es2022",
    reportCompressedSize: true,
  },
  server: {
    port: 5273,
    proxy: {
      "/api": { target: ADMIN, changeOrigin: true },
      "/metrics": { target: ADMIN, changeOrigin: true },
    },
  },
});
