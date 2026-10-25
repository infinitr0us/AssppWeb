// Re-record the current test programs using an explicitly supplied external oracle.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const oracle = process.env.KBSYNC_UNICORN_DIR;
assert(oracle, 'KBSYNC_UNICORN_DIR is required; normal test runs never record fixtures');
const sha256 = (path) =>
  createHash('sha256')
    .update(readFileSync(resolve(oracle, path)))
    .digest('hex');
const source = {
  engineSha256: sha256('engine.ts'),
  wasmSha256: sha256('vendor/unicorn.wasm'),
  glueSha256: sha256('vendor/unicorn.mjs'),
};
const temporary = mkdtempSync(resolve(tmpdir(), 'kbsync-x86-fixtures-'));
const output = resolve(temporary, 'cases.jsonl');
try {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL('../../node_modules/vitest/vitest.mjs', import.meta.url)),
      'run',
      'tests/kbsync/tsx86.test.ts',
    ],
    {
      cwd: fileURLToPath(new URL('../../', import.meta.url)),
      env: { ...process.env, KBSYNC_X86_FIXTURE_RECORD: output },
      stdio: 'inherit',
    },
  );
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'recording failed; existing fixtures were not changed');
  const cases = {};
  for (const line of readFileSync(output, 'utf8').trim().split('\n')) {
    const { program, output } = JSON.parse(line);
    assert.match(program, /^(?:[0-9a-f]{2})+$/);
    assert.equal(Buffer.from(output, 'base64').length, 0x100);
    if (cases[program] !== undefined) assert.equal(cases[program], output, 'conflicting results for the same program');
    cases[program] = output;
  }
  assert(Object.keys(cases).length > 0, 'no reference cases recorded');
  const ordered = Object.fromEntries(Object.entries(cases).sort(([a], [b]) => a.localeCompare(b)));
  const destination = new URL('./fixtures/x86-reference.json', import.meta.url);
  mkdirSync(new URL('./fixtures/', import.meta.url), { recursive: true });
  writeFileSync(destination, JSON.stringify({ format: 1, oracle: source, cases: ordered }, null, 2) + '\n');
  console.log(`Recorded ${Object.keys(cases).length} instruction programs in ${fileURLToPath(destination)}`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
