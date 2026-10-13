import { describe, expect, it } from 'vitest';
import { validateBridgeOptions } from '../src/config.js';
import { ConfigInvalidError } from '../src/errors.js';

const validBase = {
  workloadApi: { socketPath: 'unix:///run/spire/sockets/agent.sock' },
  validator: {
    allowedCallers: ['spiffe://prod.example.org/svc/*'],
    minTtlSeconds: 60,
  },
  transport: {
    mode: 'mtls-server' as const,
    sse: { host: '0.0.0.0', port: 8443 },
  },
};

describe('validateBridgeOptions', () => {
  it('accepts a minimal valid config', () => {
    const out = validateBridgeOptions(validBase);
    expect(out.workloadApi.socketPath).toBe('unix:///run/spire/sockets/agent.sock');
  });

  it('rejects empty allowedCallers list', () => {
    const bad = { ...validBase, validator: { ...validBase.validator, allowedCallers: [] } };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('rejects socketPath that is neither absolute nor unix://', () => {
    const bad = { ...validBase, workloadApi: { socketPath: 'relative/path' } };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('rejects malformed caller matcher', () => {
    const bad = {
      ...validBase,
      validator: { ...validBase.validator, allowedCallers: ['not-a-spiffe-id'] },
    };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('rejects mtls-server mode without sse config', () => {
    const bad = { ...validBase, transport: { mode: 'mtls-server' as const } };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('rejects negative minTtlSeconds', () => {
    const bad = { ...validBase, validator: { ...validBase.validator, minTtlSeconds: -5 } };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('rejects non-numeric port', () => {
    const bad = {
      ...validBase,
      transport: {
        mode: 'mtls-server' as const,
        sse: { host: '0.0.0.0', port: 'eight-thousand' as unknown as number },
      },
    };
    expect(() => validateBridgeOptions(bad)).toThrow(ConfigInvalidError);
  });

  it('surfaces the zod issues in the error message', () => {
    try {
      validateBridgeOptions({ transport: validBase.transport });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigInvalidError);
      expect((e as Error).message).toContain('workloadApi');
      expect((e as Error).message).toContain('validator');
    }
  });

  it('accepts an omitted host and rejects an empty one', () => {
    const omitted = {
      ...validBase,
      transport: { mode: 'mtls-server' as const, sse: { port: 8443 } },
    };
    expect(validateBridgeOptions(omitted).transport.sse?.host).toBeUndefined();
    const empty = {
      ...validBase,
      transport: { mode: 'mtls-server' as const, sse: { host: '', port: 8443 } },
    };
    expect(() => validateBridgeOptions(empty)).toThrow(ConfigInvalidError);
  });

  it('accepts only TLS 1.2 or 1.3 as minTlsVersion', () => {
    const withMin = (minTlsVersion: string) => ({
      ...validBase,
      transport: { ...validBase.transport, minTlsVersion },
    });
    expect(validateBridgeOptions(withMin('TLSv1.2')).transport.minTlsVersion).toBe('TLSv1.2');
    expect(validateBridgeOptions(validBase).transport.minTlsVersion).toBeUndefined();
    expect(() => validateBridgeOptions(withMin('TLSv1.1'))).toThrow(ConfigInvalidError);
  });

  it('accepts stdio-identity-only mode without sse', () => {
    const stdio = {
      ...validBase,
      transport: { mode: 'stdio-identity-only' as const },
    };
    expect(() => validateBridgeOptions(stdio)).not.toThrow();
  });
  it.each([
    { maxAttempts: -1 },
    { maxAttempts: 101 },
    { maxAttempts: 2, initialDelayMs: 0 },
    { maxAttempts: 2, initialDelayMs: 50, maxDelayMs: 10 },
  ])('refuses invalid reconnect limits %#', (reconnect) => {
    expect(() =>
      validateBridgeOptions({ ...validBase, workloadApi: { ...validBase.workloadApi, reconnect } }),
    ).toThrow(ConfigInvalidError);
  });

  it('returns parsed data without unknown keys', () => {
    const out = validateBridgeOptions({
      ...validBase,
      extra: true,
      validator: { ...validBase.validator, unexpected: 'x' },
    });
    expect(out).not.toHaveProperty('extra');
    expect(out.validator).not.toHaveProperty('unexpected');
  });

  it('is not affected by later mutation of the input', () => {
    const input = structuredClone(validBase);
    const out = validateBridgeOptions(input);
    input.validator.allowedCallers.push('spiffe://evil.example.org/*');
    input.transport.sse.host = '192.0.2.1';
    input.validator.minTtlSeconds = 0;
    expect(out.validator.allowedCallers).toEqual(['spiffe://prod.example.org/svc/*']);
    expect(out.transport.sse?.host).toBe('0.0.0.0');
    expect(out.validator.minTtlSeconds).toBe(60);
  });

  it('freezes the parsed options but not caller-owned objects', () => {
    const logger = { log: () => {} };
    const out = validateBridgeOptions({ ...validBase, audit: { logger } });
    expect(Object.isFrozen(out)).toBe(true);
    expect(Object.isFrozen(out.validator.allowedCallers)).toBe(true);
    expect(Object.isFrozen(out.transport.sse)).toBe(true);
    expect(out.audit?.logger).toBe(logger);
    expect(Object.isFrozen(logger)).toBe(false);
    expect(() => {
      (out.validator.allowedCallers as string[]).push('spiffe://evil.example.org/*');
    }).toThrow(TypeError);
  });
});
