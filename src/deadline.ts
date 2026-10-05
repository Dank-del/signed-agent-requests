/** Bounds the whole operation even when an injected transport ignores AbortSignal. */
export async function withDeadline<T>(operation: (signal: AbortSignal) => Promise<T>, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const expiry = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const error = new Error('Dependency deadline exceeded');
        controller.abort(error);
        reject(error);
      }, timeoutMs);
    });
    return await Promise.race([operation(controller.signal), expiry]);
  } finally {
    if (timer) clearTimeout(timer);
    controller.abort();
  }
}
