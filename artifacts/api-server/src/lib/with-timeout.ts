// Small, dependency-free timeout primitive shared by the agent/LLM harness.
//
// Threat model §DoS requires hard timeouts on every LLM call and every tool
// handler so a hung provider stream or a runaway tool can never wedge a chat
// turn indefinitely. `withTimeout` races an arbitrary promise against a timer
// and rejects with a typed `TimeoutError` (so callers can distinguish a
// timeout from a provider/handler error and react — e.g. degrade gracefully).

export class TimeoutError extends Error {
  readonly label: string;
  readonly timeoutMs: number;
  constructor(label: string, timeoutMs: number) {
    super(`${label} timed out after ${timeoutMs}ms`);
    this.name = "TimeoutError";
    this.label = label;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Resolve/reject with `p`, but reject with `TimeoutError` if it does not
 * settle within `timeoutMs`. A non-positive `timeoutMs` disables the timeout
 * (returns `p` unchanged). The internal timer is `unref`'d so a stray timeout
 * never keeps the Node process alive, and the original promise always has a
 * settlement handler attached so a late rejection can't surface as an
 * unhandled rejection.
 */
export function withTimeout<T>(
  p: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  if (!(timeoutMs > 0)) return p;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new TimeoutError(label, timeoutMs)),
      timeoutMs,
    );
    // Best-effort: don't let a pending timeout hold the event loop open.
    (timer as { unref?: () => void }).unref?.();
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}
