// Pack the library, then check tarball contents, secrets, exports and CJS/ESM consumers. Run after `pnpm build`.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repo = resolve(new URL('..', import.meta.url).pathname);
const pkg = JSON.parse(await readFile(join(repo, 'package.json'), 'utf8'));
const work = await mkdtemp(join(tmpdir(), 'bridge-pack-'));
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: 'pipe', encoding: 'utf8' });

try {
  run('pnpm', ['pack', '--pack-destination', work], repo);
  const tarball = join(work, `${pkg.name}-${pkg.version}.tgz`);
  const entries = run('tar', ['-tzf', tarball], work)
    .split('\n')
    .filter(Boolean)
    .map((e) => e.replace(/^package\//, ''));

  const allowed =
    /^(package\.json|README\.md|LICENSE|NOTICE|dist\/[\w/-]+\.(js|cjs|d\.ts|d\.cts|js\.map|cjs\.map))$/;
  const unexpected = entries.filter((e) => !allowed.test(e));
  assert.deepEqual(unexpected, [], `unexpected tarball entries: ${unexpected.join(', ')}`);

  const consumer = join(work, 'consumer');
  const installed = join(consumer, 'node_modules', pkg.name);
  await mkdir(installed, { recursive: true });
  run('tar', ['-xzf', tarball, '-C', installed, '--strip-components=1'], work);

  const forbidden = [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\/Users\/[a-z]/, /op:\/\//];
  for (const entry of entries) {
    const text = await readFile(join(installed, entry), 'utf8');
    for (const pattern of forbidden) assert(!pattern.test(text), `${entry} matches ${pattern}`);
  }

  const targets = [];
  const walk = (node) => {
    if (typeof node === 'string') targets.push(node.replace(/^\.\//, ''));
    else if (node && typeof node === 'object') for (const v of Object.values(node)) walk(v);
  };
  walk(pkg.exports);
  for (const field of ['main', 'module', 'types']) walk(pkg[field]);
  const missing = targets.filter((t) => !entries.includes(t));
  assert.deepEqual(missing, [], `export targets missing from tarball: ${missing.join(', ')}`);

  const deps = [...Object.keys(pkg.dependencies ?? {}), '@types/node'];
  for (const dep of deps) {
    const link = join(consumer, 'node_modules', dep);
    await mkdir(resolve(link, '..'), { recursive: true });
    await symlink(await realpath(join(repo, 'node_modules', dep)), link);
  }
  const probe = `import { FileAuditLogger, createMcpSpiffeBridge, type BridgeOptions } from '${pkg.name}';\nexport const used: [unknown, unknown, BridgeOptions | null] = [FileAuditLogger, createMcpSpiffeBridge, null];\n`;
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"commonjs"}\n');
  await writeFile(join(consumer, 'cjs.ts'), probe);
  await writeFile(join(consumer, 'esm.mts'), probe);
  await writeFile(
    join(consumer, 'tsconfig.json'),
    JSON.stringify({
      compilerOptions: {
        module: 'node16',
        moduleResolution: 'node16',
        target: 'ES2023',
        strict: true,
        noEmit: true,
        skipLibCheck: false,
        types: ['node'],
      },
      files: ['cjs.ts', 'esm.mts'],
    }),
  );
  run(join(repo, 'node_modules', '.bin', 'tsc'), ['-p', consumer], consumer);

  const expected = 'function,function';
  const cjs = run(
    'node',
    [
      '-e',
      `const m=require('${pkg.name}');console.log([typeof m.FileAuditLogger,typeof m.createMcpSpiffeBridge].join())`,
    ],
    consumer,
  ).trim();
  const esm = run(
    'node',
    [
      '--input-type=module',
      '-e',
      `const m=await import('${pkg.name}');console.log([typeof m.FileAuditLogger,typeof m.createMcpSpiffeBridge].join())`,
    ],
    consumer,
  ).trim();
  assert.equal(cjs, expected, 'CommonJS runtime exports');
  assert.equal(esm, expected, 'ESM runtime exports');

  const listed = (await readdir(installed, { recursive: true })).length;
  console.log(JSON.stringify({ passed: true, entries: entries.length, files: listed }));
} finally {
  await rm(work, { recursive: true, force: true });
}
