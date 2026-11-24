import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  // Declarations come from tsc: tsup's dts build needs the TypeScript 6 compiler API.
  dts: false,
  clean: true,
  sourcemap: true,
  target: 'node26',
  splitting: false,
  treeshake: true,
});
