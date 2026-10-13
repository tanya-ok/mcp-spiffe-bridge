import { AsyncLocalStorage } from 'node:async_hooks';
import type { SpiffeCallContext, ValidatedIdentity } from '../types.js';

/**
 * Per-request caller identity store.
 *
 * MCP tool handlers run inside the same async context as the request that
 * invoked them, so we can use Node's `AsyncLocalStorage` to thread identity
 * through without modifying the MCP SDK's context shape.
 *
 * Usage in transport layer:
 *
 *   callerContext.run({ caller, requestId }, () => {
 *     return mcpServer.handle(request);
 *   });
 *
 * Usage in a tool handler:
 *
 *   const caller = getCallerIdentity();
 *   if (!caller) throw new Error('no caller identity');
 */
export const callerContext = new AsyncLocalStorage<SpiffeCallContext>();

/**
 * Return the caller identity for the current async context, or `null` if
 * none was attached (e.g. degrade mode `warn-and-skip`, or a code path that
 * runs outside a validated request).
 */
export function getCallerIdentity(): ValidatedIdentity | null {
  const ctx = callerContext.getStore();
  return ctx?.caller ?? null;
}

/**
 * Return the full context (caller + requestId) for the current async scope.
 * Use this when you need the request ID for audit correlation.
 */
export function getCallContext(): SpiffeCallContext | null {
  return callerContext.getStore() ?? null;
}

/**
 * Run `fn` with the given caller context. The transport layer calls this
 * once per validated incoming request, after the TLS handshake and SPIFFE
 * validation succeed.
 */
export function runWithCallContext<T>(ctx: SpiffeCallContext, fn: () => T): T {
  return callerContext.run(ctx, fn);
}
