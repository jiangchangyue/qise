/** Browser mock of `@tauri-apps/api/app` (browser-preview mode only). */

export async function getVersion(): Promise<string> {
  return "0.2.1";
}

export async function getName(): Promise<string> {
  return "Qise (browser preview)";
}
