// Write a .d.cts sibling for every emitted .d.ts so require() consumers get CommonJS-typed declarations.
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const root = new URL('../dist/', import.meta.url).pathname;
const relative = /((?:from|import)\s*\(?\s*['"])(\.{1,2}\/[^'"]+)\.js(['"])/g;

async function* declarations(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* declarations(path);
    else if (entry.name.endsWith('.d.ts')) yield path;
  }
}

let count = 0;
for await (const path of declarations(root)) {
  const source = await readFile(path, 'utf8');
  await writeFile(path.replace(/\.d\.ts$/, '.d.cts'), source.replace(relative, '$1$2.cjs$3'));
  count++;
}
if (count === 0) throw new Error('no declarations found in dist');
