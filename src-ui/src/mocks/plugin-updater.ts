/**
 * Browser mock of `@tauri-apps/plugin-updater` (browser-preview mode only).
 * Reports "already up to date" so the Settings page shows the green state.
 */

export interface UpdateDownloadEvent {
  event: "Started" | "Progress" | "Finished";
  data?: { contentLength?: number; chunkLength?: number };
}

export class Update {
  version: string;

  constructor(version: string) {
    this.version = version;
  }

  async downloadAndInstall(
    onEvent?: (event: UpdateDownloadEvent) => void,
  ): Promise<void> {
    onEvent?.({ event: "Started", data: { contentLength: 1024 } });
    onEvent?.({ event: "Progress", data: { chunkLength: 1024 } });
    onEvent?.({ event: "Finished" });
  }

  async close(): Promise<void> {}
}

export async function check(): Promise<Update | null> {
  return null; // null => current install is up to date
}
