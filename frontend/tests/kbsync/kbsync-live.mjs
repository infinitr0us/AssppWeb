// Generates kbsync with the real Apple assets (no network).
// Run with: KBSYNC_ASSET_DIR=<dir with the five assets> npx tsx tests/kbsync/kbsync-live.mjs
// Defaults to the production JIT engine; KBSYNC_ENGINE=ts selects the interpreter.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mock } from 'node:test';
import { GuestEngine } from '../../src/apple/kbsync/engine.ts';
import { generateKBSync } from '../../src/apple/kbsync/storeAgent.ts';
import { TsX86Engine } from '../../src/apple/kbsync/tsx86.ts';

const dir = process.env.KBSYNC_ASSET_DIR;
if (!dir) throw new Error('KBSYNC_ASSET_DIR is required');
const read = (name) => new Uint8Array(readFileSync(`${dir}/${name}`));
const assets = {
  commerceKit: read('CommerceKit'),
  commerceCore: read('CommerceCore'),
  coreFP: read('CoreFP'),
  coreFPICXS: read('CoreFP.icxs'),
  storeAgent: read('storeagent'),
};
const engineName = process.env.KBSYNC_ENGINE ?? 'jit';
assert(['ts', 'jit'].includes(engineName), 'KBSYNC_ENGINE must be ts or jit');
if (engineName === 'ts') {
  mock.method(GuestEngine, 'open', async () => new TsX86Engine());
}
const run = TsX86Engine.prototype.emuStart;
mock.method(TsX86Engine.prototype, 'emuStart', function (begin, until, timeoutUs, count) {
  const started = performance.now();
  const before = this.instructionCount;
  try {
    // The interpreter needs a longer offline bound; JIT keeps production timeouts.
    return run.call(this, begin, until, engineName === 'ts' ? 20 * 60 * 1_000_000 : timeoutUs, count);
  } finally {
    console.log(
      `guest 0x${begin.toString(16)}: ${(performance.now() - started).toFixed(2)}ms, ${this.instructionCount - before} instructions`,
    );
    if (this.jit) {
      console.log(
        `JIT compilation: ${this.jit.compilationMs.toFixed(2)}ms, ${this.jit.compilations} blocks, ${this.jit.invalidations} invalidations`,
      );
      console.log(
        `JIT: ${this.jit.compiledInstructions} compiled, ${this.jit.fallbackInstructions} interpreted; hot fallbacks:`,
        [...this.jit.fallbackAddresses]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([pc, n]) => [pc.toString(16), n]),
      );
    }
  }
});

const hardwareID = Uint8Array.from([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]);
const started = Date.now();
try {
  const kbsync = await generateKBSync(assets, hardwareID, 12345678901);
  assert.equal(kbsync.length, 196, 'kbsync length');
  assert.deepEqual([...kbsync.subarray(0, 4)], [0, 4, 0, 3], 'kbsync prefix');
  console.log(`kbsync (${engineName}): ${kbsync.length} bytes in ${Date.now() - started}ms`);
  console.log(
    Buffer.from(kbsync)
      .toString(process.env.KBSYNC_FULL ? 'hex' : 'base64')
      .slice(0, process.env.KBSYNC_FULL ? undefined : 48),
  );
} finally {
  mock.restoreAll();
}
