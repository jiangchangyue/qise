/** Browser mock of `@tauri-apps/plugin-process` (browser-preview mode only). */

export async function relaunch(): Promise<void> {
  console.info("[browser-mock] relaunch requested; reloading the page instead.");
  window.location.reload();
}

export async function exit(): Promise<void> {
  console.info("[browser-mock] exit requested (no-op in the browser).");
}
