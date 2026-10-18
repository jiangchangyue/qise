/**
 * Browser mock of `@tauri-apps/api/event` (used only in browser-preview mode).
 * A tiny in-memory event bus wired to the demo backend in tauri-core.ts.
 */

type EventCallback<T> = (event: { payload: T }) => void;

const listeners = new Map<string, Set<EventCallback<unknown>>>();

export function emitToBus<T>(name: string, payload: T): void {
  const handlers = listeners.get(name);
  if (!handlers) return;
  handlers.forEach((handler) => {
    try {
      handler({ payload });
    } catch (error) {
      console.error(`[browser-mock] listener for "${name}" failed`, error);
    }
  });
}

export async function listen<T>(
  eventName: string,
  handler: EventCallback<T>,
): Promise<() => void> {
  let handlers = listeners.get(eventName);
  if (!handlers) {
    handlers = new Set();
    listeners.set(eventName, handlers);
  }
  const wrapped = handler as EventCallback<unknown>;
  handlers.add(wrapped);
  return () => {
    handlers?.delete(wrapped);
  };
}

export async function emit<T>(eventName: string, payload?: T): Promise<void> {
  emitToBus(eventName, payload);
}
