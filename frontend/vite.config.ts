import path from "path";
import fs from "fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";

function resolveTsAlias() {
  return {
    name: "resolve-ts-alias",
    enforce: "pre" as const,
    resolveId(source: string) {
      if (source.startsWith("@/")) {
        const relativePath = source.replace(/^@\//, "");
        const basePath = path.resolve(__dirname, "src", relativePath);

        const candidates = [
          basePath,
          `${basePath}.tsx`,
          `${basePath}.ts`,
          `${basePath}.jsx`,
          `${basePath}.js`,
          `${basePath}.json`,
          path.join(basePath, "index.tsx"),
          path.join(basePath, "index.ts"),
          path.join(basePath, "index.jsx"),
          path.join(basePath, "index.js"),
        ];

        for (const candidate of candidates) {
          if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
            return candidate.replace(/\\/g, "/");
          }
        }
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [
    resolveTsAlias(),
    TanStackRouterVite({
      target: "react",
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src").replace(/\\/g, "/"),
    },
  },
  server: {
    port: 3000,
    proxy: {
      // Proxy ONLY /api requests to the backend server on port 8000.
      // This prevents collisions with frontend SPA page routes (e.g., /projects/123/vulnerabilities/456).
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
