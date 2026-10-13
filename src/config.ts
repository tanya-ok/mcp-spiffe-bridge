import { z } from 'zod';
import { ConfigInvalidError } from './errors.js';
import type { BridgeOptions } from './types.js';

// A caller-matcher is a SPIFFE-ID or glob of one. We don't fully parse it
// here (the runtime matcher does), but we reject obviously malformed
// strings at startup so typos fail fast.
const callerMatcherSchema = z
  .string()
  .min(1)
  .regex(/^spiffe:\/\/[a-z0-9._*-]+(\/[A-Za-z0-9._~!$&'()*+,;=:@*-]+)*$/, {
    message: 'must look like `spiffe://<trust-domain>/<path>` (wildcards `*` and `**` allowed)',
  });

const socketPathSchema = z
  .string()
  .min(1)
  .refine((v) => v.startsWith('unix://') || v.startsWith('/'), {
    message: 'must be an absolute path or a `unix://` URI',
  });

const workloadApiSchema = z.object({
  socketPath: socketPathSchema,
  connectTimeoutMs: z.number().int().positive().optional(),
  rpcTimeoutMs: z.number().int().positive().optional(),
  reconnect: z
    .object({
      maxAttempts: z.number().int().min(0).max(100),
      initialDelayMs: z.number().int().min(1).max(60_000).optional(),
      maxDelayMs: z.number().int().min(1).max(60_000).optional(),
    })
    .refine(
      (v) => (v.maxDelayMs ?? 5000) >= (v.initialDelayMs ?? 250),
      'maxDelayMs must be at least initialDelayMs',
    )
    .optional(),
});

const validatorSchema = z.object({
  allowedCallers: z.array(callerMatcherSchema).min(1, {
    message: 'at least one allowedCaller is required; an empty list denies every peer',
  }),
  minTtlSeconds: z.number().int().nonnegative(),
  allowedTrustDomains: z.array(z.string().min(1)).optional(),
});

const transportSchema = z.object({
  mode: z.enum(['mtls-server', 'stdio-identity-only']),
  minTlsVersion: z.enum(['TLSv1.2', 'TLSv1.3']).optional(),
  sse: z
    .object({
      host: z.string().min(1).optional(),
      port: z.number().int().min(1).max(65535),
    })
    .optional(),
});

const degradeSchema = z.object({
  mode: z.enum(['fail-fast', 'warn-and-skip']),
  // fakeSvid shape is not validated here; it's a runtime object, not JSON config.
  fakeSvid: z.unknown().optional(),
});

const auditSchema = z.object({
  // logger is a function/object, not JSON-serializable; we pass it through as unknown.
  logger: z.unknown().optional(),
});

const bridgeOptionsSchema = z.object({
  workloadApi: workloadApiSchema,
  validator: validatorSchema,
  transport: transportSchema,
  audit: auditSchema.optional(),
  degrade: degradeSchema.optional(),
});

/**
 * Validate user-supplied options at startup. Throws `ConfigInvalidError`
 * with a human-readable summary when validation fails.
 *
 * Returns a frozen copy of the parsed options: unknown keys are dropped and
 * later changes to the input have no effect. The cast restores branded types.
 */
export function validateBridgeOptions(input: unknown): BridgeOptions {
  const result = bridgeOptionsSchema.safeParse(input);
  if (!result.success) {
    const summary = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ConfigInvalidError(`invalid BridgeOptions:\n${summary}`, { cause: result.error });
  }
  // Cross-field rule: mtls-server requires sse config.
  const v = result.data;
  if (v.transport.mode === 'mtls-server' && !v.transport.sse) {
    throw new ConfigInvalidError(
      'transport.mode = "mtls-server" requires transport.sse.{host,port}',
    );
  }
  const opaque = new Set<unknown>([v.audit?.logger, v.degrade?.fakeSvid]);
  return deepFreeze(v, opaque) as unknown as BridgeOptions;
}

function deepFreeze<T>(value: T, opaque: ReadonlySet<unknown>): T {
  if (value === null || typeof value !== 'object' || opaque.has(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child, opaque);
  return Object.freeze(value);
}
