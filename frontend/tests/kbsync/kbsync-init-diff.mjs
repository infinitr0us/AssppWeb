// Offline lockstep initialization: Unicorn executes each instruction, then TS
// receives its RDTSC result. Loader/shim writes are mirrored; shim reads and
// block-entry registers are compared before the reference can mask a mismatch.
// KBSYNC_ASSET_DIR=<assets> npx tsx tests/kbsync/kbsync-init-diff.mjs
// Requires KBSYNC_UNICORN_DIR pointing to the external reference engine.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mock } from 'node:test';
import { GuestEngine, X86_REG } from '../../src/apple/kbsync/engine.ts';
import { TsX86Engine } from '../../src/apple/kbsync/tsx86.ts';
import { generateKBSync } from '../../src/apple/kbsync/storeAgent.ts';
import { openUnicornReference } from './unicorn-reference.mjs';

const dir = process.env.KBSYNC_ASSET_DIR;
assert(dir, 'KBSYNC_ASSET_DIR is required');
const read = (name) => new Uint8Array(readFileSync(`${dir}/${name}`));
const assets = {
  commerceKit: read('CommerceKit'),
  commerceCore: read('CommerceCore'),
  coreFP: read('CoreFP'),
  coreFPICXS: read('CoreFP.icxs'),
  storeAgent: read('storeagent'),
};
const reference = await openUnicornReference();
const useJit = process.env.KBSYNC_ENGINE === 'jit';
const actual = new TsX86Engine({ jit: useJit });
const registerIds = [35, 38, 40, 37, 44, 36, 43, 39, 106, 107, 108, 109, 110, 111, 112, 113];
const registerNames = [
  'rax',
  'rcx',
  'rdx',
  'rbx',
  'rsp',
  'rbp',
  'rsi',
  'rdi',
  'r8',
  'r9',
  'r10',
  'r11',
  'r12',
  'r13',
  'r14',
  'r15',
];
const lowRegisterIds = [19, 22, 24, 21, 30, 20, 29, 23, 226, 227, 228, 229, 230, 231, 232, 233];
function exactRegister(rounded, low) {
  // f64 loses at most 11 low bits. The exact low dword resolves any carry into the high dword.
  return (BigInt(Math.round((rounded - low) / 4294967296)) << 32n) | BigInt(low);
}
for (const value of [0n, 1n, 0x123456789abcdefn, 0x7fffffffffffffffn, 0xffffffffffffffffn]) {
  assert.equal(exactRegister(Number(value), Number(value & 0xffffffffn)), value);
}
const hooks = [];
const regions = [];
const recent = [];
const detailLo = Number(process.env.DIFF_LO ?? '0');
const detailHi = Number(process.env.DIFF_HI ?? '0');
const watchAddress = Number(process.env.WATCH_ADDRESS ?? '0');
let instructions = 0;
let previousEnd = -1;
let pendingRdtsc = false;
let stopped = false;
const started = Date.now();
let pendingWrites = [];
let stepping = false;
// Force write instrumentation even when the JIT can prove a write misses code.
actual.watchRange(0, 0);
const noteWrite = actual.noteWrite.bind(actual);
actual.noteWrite = (address, value, size) => {
  noteWrite(address, value, size);
  if (stepping) pendingWrites.push({ address, size, rip: actual.regRead(X86_REG.RIP) });
};
const writeMemory = actual.memWrite.bind(actual);
actual.memWrite = (address, data) => {
  actual.noteWrite(address, 0, data.length);
  writeMemory(address, data);
};
function checkWrites() {
  for (const { address, size, rip } of pendingWrites) {
    assert.deepEqual(
      actual.memRead(address, size),
      reference.memRead(address, size),
      `write by 0x${rip.toString(16)} to 0x${address.toString(16)} at instruction ${instructions}`,
    );
  }
  pendingWrites = [];
}

const mirror = {
  onCodeHook: null,
  memMap(address, size) {
    reference.memMap(address, size);
    // The vendored WASM allocator can reuse dirty RAM; both engines must start with identical BSS.
    reference.memWrite(address, new Uint8Array(size));
    actual.memMap(address, size);
    regions.push({ address, size });
  },
  memWrite(address, data) {
    reference.memWrite(address, data);
    actual.memWrite(address, data);
  },
  memRead(address, size) {
    const expected = reference.memRead(address, size);
    assert.deepEqual(actual.memRead(address, size), expected, `shim memory read at 0x${address.toString(16)}`);
    return expected;
  },
  regWrite(id, value) {
    reference.regWrite(id, value);
    actual.regWrite(id, value);
  },
  regRead(id) {
    const expected = reference.regRead(id);
    assert.equal(actual.regRead(id), expected, `shim register read ${id}`);
    return expected;
  },
  attachCodeHook() {},
  addCodeHook(begin, end) {
    hooks.push({ begin, end });
    actual.addCodeHook(begin, end);
    return hooks.length;
  },
  hookDel() {},
  close() {},
  emuStop() {
    stopped = true;
    reference.emuStop();
  },
  emuStart(begin, until) {
    for (const { address, size } of regions) {
      assert.deepEqual(
        actual.memRead(address, size),
        reference.memRead(address, size),
        `memory before call 0x${address.toString(16)}`,
      );
    }
    actual.regWrite(X86_REG.RIP, begin);
    previousEnd = -1;
    expectedSteps = [];
    expectedIndex = 0;
    previousBlock = null;
    callUntil = until;
    pendingRdtsc = false;
    stopped = false;
    // This diagnostic is slower than either engine alone; keep a finite limit.
    reference.emuStart(begin, until, 30 * 60 * 1_000_000, 0);
    checkWrites();
    assert.equal(actual.regRead(X86_REG.RIP), reference.regRead(X86_REG.RIP), 'call return address');
    for (const { address, size } of regions) {
      assert.deepEqual(
        actual.memRead(address, size),
        reference.memRead(address, size),
        `memory at call return 0x${address.toString(16)}`,
      );
    }
    if (useJit) assert.equal(expectedIndex, expectedSteps.length, 'all compiled instructions checked');
    console.log(`call 0x${begin.toString(16)} matched; ${instructions} instructions, ${Date.now() - started}ms`);
    if (useJit)
      console.log(`JIT: ${actual.jit.compiledInstructions} compiled instructions, ${boundaries} boundaries checked`);
  },
};

reference.attachCodeHook();
reference.addCodeHook(1, 0x10000000000000);
const stepReference = (address, size) => {
  checkWrites();
  if (pendingRdtsc) {
    actual.regWrite(X86_REG.RAX, reference.regRead(X86_REG.RAX));
    actual.regWrite(X86_REG.RDX, reference.regRead(X86_REG.RDX));
    pendingRdtsc = false;
  }
  assert.equal(actual.regRead(X86_REG.RIP), address, `control flow at instruction ${instructions}`);
  if (address !== previousEnd || (address >= detailLo && address < detailHi)) {
    if (watchAddress)
      assert.deepEqual(
        actual.memRead(watchAddress, 8),
        reference.memRead(watchAddress, 8),
        `watched memory 0x${watchAddress.toString(16)} at instruction ${instructions}, 0x${address.toString(16)}`,
      );
    for (let i = 0; i < registerIds.length; i++) {
      // Compare all 64 bits using the full-register and low-dword oracle reads.
      assert.equal(
        actual.regQword(i),
        exactRegister(reference.regRead(registerIds[i]), reference.regRead(lowRegisterIds[i])),
        `${registerNames[i]} at instruction ${instructions}, 0x${address.toString(16)}`,
      );
    }
  }
  previousEnd = address + size;
  recent.push(address);
  if (recent.length > 16) recent.shift();
  if (hooks.some((hook) => address >= hook.begin && address <= hook.end)) mirror.onCodeHook?.(address, size);
  if (stopped) return;
  pendingRdtsc = actual.read8(address) === 0x0f && actual.read8(address + 1) === 0x31;
  // RDTSC is supplied at the next boundary; executing it here only advances RIP.
  stepping = true;
  actual.regWrite(X86_REG.RIP, actual.step());
  stepping = false;
  assert.equal(actual.lastSize, size, `instruction length at 0x${address.toString(16)}`);
  instructions++;
  if (instructions % 10_000_000 === 0) console.log(`${instructions} instructions matched in ${Date.now() - started}ms`);
};

// Optimized mode executes a bounded batch of compiled blocks ahead, then checks every
// reference PC/length and all registers/writes when Unicorn reaches its exit.
let expectedSteps = [];
let expectedIndex = 0;
let previousBlock = null;
let callUntil = 0;
let boundaries = 0;
let nextProgress = 10_000_000;
actual.onJitBlock = () => actual.emuStop();
reference.onCodeHook = useJit
  ? (address, size) => {
      if (expectedIndex === expectedSteps.length) {
        checkWrites();
        if (pendingRdtsc) {
          actual.regWrite(X86_REG.RAX, reference.regRead(X86_REG.RAX));
          actual.regWrite(X86_REG.RDX, reference.regRead(X86_REG.RDX));
          pendingRdtsc = false;
        }
        assert.equal(actual.regRead(X86_REG.RIP), address, `JIT exit at instruction ${instructions}`);
        for (let i = 0; i < registerIds.length; i++) {
          assert.equal(
            actual.regQword(i),
            exactRegister(reference.regRead(registerIds[i]), reference.regRead(lowRegisterIds[i])),
            `${registerNames[i]} at instruction ${instructions}, 0x${address.toString(16)}`,
          );
        }
        boundaries++;
        if (hooks.some((hook) => address >= hook.begin && address <= hook.end)) mirror.onCodeHook?.(address, size);
        if (stopped) return;
        actual.jit.executionLog = [];
        const before = actual.instructionCount;
        stepping = true;
        actual.emuStart(address, callUntil);
        stepping = false;
        const count = actual.instructionCount - before;
        const blocks = actual.jit.executionLog;
        expectedSteps = blocks.flatMap(({ block, count }) => block.instructions.slice(0, count));
        const firstBlock = blocks[0]?.block;
        if (
          previousBlock?.valid &&
          firstBlock?.start === address &&
          previousBlock.next0 !== firstBlock &&
          previousBlock.next1 !== firstBlock
        ) {
          previousBlock.next0 = previousBlock.next1;
          previousBlock.next1 = firstBlock;
        }
        previousBlock = blocks.at(-1)?.block ?? null;
        if (!blocks.length) {
          assert.equal(count, 1, 'interpreter fallback executes one instruction');
          expectedSteps = [{ address, size: actual.lastSize }];
          pendingRdtsc = actual.read8(address) === 0x0f && actual.read8(address + 1) === 0x31;
        }
        assert.equal(expectedSteps.length, count, 'block log covers every executed instruction');
        expectedIndex = 0;
      }
      const expected = expectedSteps[expectedIndex++];
      if (expected.address !== address)
        assert.equal(expected.address, address, `compiled control flow at instruction ${instructions}`);
      if (expected.size !== size)
        assert.equal(expected.size, size, `compiled instruction length at 0x${address.toString(16)}`);
      recent.push(address);
      if (recent.length > 16) recent.shift();
      instructions++;
      if (instructions >= nextProgress) {
        console.log(`${instructions} instructions matched in ${Date.now() - started}ms`);
        nextProgress += 10_000_000;
      }
    }
  : stepReference;

mock.method(GuestEngine, 'open', async () => mirror);
try {
  const output = await generateKBSync(assets, Uint8Array.from([10, 27, 44, 61, 78, 95]), 12345678901);
  assert.equal(output.length, 196);
  assert.deepEqual([...output.subarray(0, 4)], [0, 4, 0, 3]);
  console.log('init + final call matched, including stack/shim memory and output');
} catch (error) {
  console.error(
    'TS registers:',
    actual
      .gprs()
      .map((_, i) => `${registerNames[i]}=0x${actual.regQword(i).toString(16)}`)
      .join(' '),
  );
  console.error(`last ${recent.length} instructions: ${recent.map((pc) => `0x${pc.toString(16)}`).join(' ')}`);
  throw error;
} finally {
  mock.restoreAll();
  reference.close();
}
