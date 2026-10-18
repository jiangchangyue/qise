import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const host = process.env.TAURI_DEV_HOST;

// Opt-in UI preview: reuse the desktop components with local sample data.
// Normal dev/build commands keep the real Tauri APIs.
const here = path.dirname(fileURLToPath(import.meta.url));
const mock = (p: string) => path.resolve(here, "src/mocks", p);

export default defineConfig(({ mode }) => {
  const browserMock = mode === "browser" || process.env.VITE_BROWSER_MOCK === "1";
  return {
    plugins: [react()],
    define: {
      __QISE_BROWSER_PREVIEW__: JSON.stringify(browserMock),
    },
    resolve: browserMock
      ? {
          alias: {
            "@tauri-apps/api/core": mock("tauri-core.ts"),
            "@tauri-apps/api/event": mock("tauri-event.ts"),
            "@tauri-apps/api/app": mock("tauri-app.ts"),
            "@tauri-apps/plugin-process": mock("plugin-process.ts"),
            "@tauri-apps/plugin-updater": mock("plugin-updater.ts"),
          },
        }
      : undefined,
    clearScreen: false,
    server: {
      port: 1420,
      strictPort: true,
      host: browserMock ? "127.0.0.1" : host || false,
      hmr: !browserMock && host
        ? {
            protocol: "ws",
            host,
            port: 1421,
          }
        : undefined,
      watch: {
        ignored: ["**/src-tauri/**"],
      },
    },
  };
});
