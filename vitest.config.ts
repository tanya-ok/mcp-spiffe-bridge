import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // @peculiar/x509 2 resolves its ASN.1 schemas through tsyringe, which needs this polyfill.
    setupFiles: ['reflect-metadata'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
    },
  },
});
