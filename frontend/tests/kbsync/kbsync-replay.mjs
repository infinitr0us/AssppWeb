// Differential replay: runs the captured kbsync final call on the pure-TS
// x86-64 engine and compares the instruction sequence + output against the
// Unicorn capture. Run: npx tsx tests/kbsync/kbsync-replay.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TsX86Engine, X86_REG } from '../../src/apple/kbsync/tsx86.ts';
import { Shims } from '../../src/apple/kbsync/shims.ts';
import { toInt32 } from '../../src/apple/kbsync/machine.ts';

const DIR = process.env.REPLAY_DIR ?? '/tmp/asspp-sap/replay';
const benchmark = process.env.REPLAY_BENCH === '1';
const meta = JSON.parse(readFileSync(`${DIR}/meta.json`, 'utf8'));
const shimsState = JSON.parse(readFileSync(`${DIR}/shims.json`, 'utf8'));
const entryRegs = JSON.parse(readFileSync(`${DIR}/entry-regs.json`, 'utf8'));
const rdtscPairs = JSON.parse(readFileSync(`${DIR}/rdtsc.json`, 'utf8'));
const expectedOutput = new Uint8Array(readFileSync(`${DIR}/output.bin`));

// trace as numbers
const tbuf = readFileSync(`${DIR}/trace.f64`);
const tview = new DataView(tbuf.buffer, tbuf.byteOffset, tbuf.byteLength);
const traceLen = tbuf.byteLength / 8;
const traceAt = (i) => tview.getFloat64(i * 8, true);

const blockBuffer = readFileSync(`${DIR}/blockregs.f64`);
const blockView = new DataView(blockBuffer.buffer, blockBuffer.byteOffset, blockBuffer.byteLength);
const expectedBlock = (row, col) => blockView.getFloat64((row * 9 + col) * 8, true);
const blockNames = ['rip', 'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r11'];
const blockRows = blockBuffer.byteLength / 72;
assert(Number.isInteger(blockRows) && blockRows > 0, 'invalid block register trace');
assert(Number.isInteger(traceLen) && traceLen > 0, 'invalid instruction trace');
assert(rdtscPairs.length % 2 === 0, 'invalid RDTSC pairs');
const rdtscValues = [];
for (let i = 0; i < rdtscPairs.length; i += 2) {
  rdtscValues.push(rdtscPairs[i] + rdtscPairs[i + 1] * 4294967296);
}

const RETURN_ADDRESS = 0x0000000100000000;
const STACK_END =
  meta.regions.find((r) => r.name === 'stack').address + meta.regions.find((r) => r.name === 'stack').size;

// deterministic shims (same contract as capture)
let lcgState = meta.lcgStateAfterInit;
const lcgNext = () => {
  lcgState = (Math.imul(lcgState, 1103515245) + 12345) & 0x7fffffff;
  return lcgState >>> 0;
};
const FIXED_NOW_MS = meta.fixedNow;

// ---- build engine + memory ----
const engine = new TsX86Engine({ jit: process.env.KBSYNC_ENGINE === 'jit' });
for (const r of meta.regions) engine.memMap(r.address, r.size);
for (const r of meta.regions) {
  engine.memWrite(r.address, new Uint8Array(readFileSync(`${DIR}/mem-${r.name}.bin`)));
}

// ---- shims: rebuild then overlay captured layout/state ----
const assetDir = process.env.KBSYNC_ASSET_DIR ?? '/tmp/asspp-sap/sap-assets';
const services = await Shims.open(
  engine,
  Object.fromEntries(meta.exports),
  new Uint8Array(readFileSync(`${assetDir}/CoreFP.icxs`)),
  {
    zeroReturnAliases: [
      '_pthread_rwlock_rdlock',
      '_pthread_rwlock_rdlock$UNIX2003',
      '_pthread_mutex_init',
      '_pthread_mutex_destroy',
      '_pthread_rwlock_destroy',
    ],
  },
);
const freshSymbols = new Map(services.symbols);
const freshHandlers = new Map(services.handlers);
// overlay: adopt captured addresses
services.symbols.clear();
services.handlers.clear();
services.entries.clear();
for (const [name, addr] of shimsState.symbols) {
  services.symbols.set(name, addr);
  if (freshSymbols.has(name)) {
    services.handlers.set(addr, freshHandlers.get(freshSymbols.get(name)));
    services.entries.set(addr, name);
  } else {
    services.entries.set(addr, name);
    services.handlers.set(addr, () => {
      throw new Error(`guest called unsupported import ${name}`);
    });
  }
}
services.epilogue = shimsState.epilogue;
services.errnoAddress = shimsState.errnoAddress;
services.codeCursor = shimsState.codeCursor;
services.dataCursor = shimsState.dataCursor;
services.heapCursor = shimsState.heapCursor;
for (const [k, v] of shimsState.allocations) services.allocations.set(Number(k), v);
services.freeBlocks = shimsState.freeBlocks.map((b) => ({ address: b.address, size: b.size }));
services.iterator = shimsState.iterator;
services.icxsOffset = shimsState.icxsOffset;

// deterministic overrides (same as capture)
const detHandlers = services.handlers;
function overrideShim(name, fn) {
  const addr = services.symbols.get(name);
  detHandlers.set(addr, fn);
}
overrideShim('_arc4random', () => {
  engine.regWrite(X86_REG.RAX, lcgNext());
});
overrideShim('_gettimeofday', () => {
  const timeAddress = engine.regRead(X86_REG.RDI);
  const zoneAddress = engine.regRead(X86_REG.RSI);
  if (timeAddress !== 0) {
    const data = new Uint8Array(16);
    const view = new DataView(data.buffer);
    view.setBigUint64(0, BigInt(Math.floor(FIXED_NOW_MS / 1000)), true);
    view.setUint32(8, (FIXED_NOW_MS % 1000) * 1000, true);
    engine.memWrite(timeAddress, data);
  }
  if (zoneAddress !== 0) engine.memWrite(zoneAddress, new Uint8Array(8));
  engine.regWrite(X86_REG.RAX, 0);
});

// ---- entry state ----
engine.replayRdtsc(rdtscValues);
// leftover caller-saved registers recorded at the unicorn call boundary
engine.regWrite(X86_REG.R11, entryRegs.r11);
const SHIM_BASE = 0x0000200000000000;
const SHIM_CODE_SIZE = 0x80000;
const prevHook = engine.onCodeHook;
let instructionIndex = 0;
let blockIndex = 0;
const blockRegisters = [
  X86_REG.RAX,
  X86_REG.RCX,
  X86_REG.RDX,
  X86_REG.RSI,
  X86_REG.RDI,
  X86_REG.R8,
  X86_REG.R9,
  X86_REG.R11,
];
const regTraceLo = Number(process.env.REG_LO ?? '0');
const regTraceHi = Number(process.env.REG_HI ?? '0');
let tracing = false;
let tsPrevEnd = -1; // updated after each step in emuStart via engine.lastSize
if (!benchmark)
  engine.onCodeHook = (address, size) => {
    lastStepHooked = true;
    if (tracing) {
      const index = instructionIndex;
      if (index >= traceLen || traceAt(index) !== address) {
        throw new Error(
          `instruction ${index}: expected 0x${index < traceLen ? traceAt(index).toString(16) : 'end'}, got 0x${address.toString(16)}`,
        );
      }
      // engine.lastSize at hook time = size of the PREVIOUS instruction
      if (instructionIndex === 0 || address !== tsPrevEnd) {
        const values = [address, ...blockRegisters.map((id) => engine.regRead(id))];
        const row = blockIndex;
        assert(row < blockRows, `unexpected block ${row} at instruction ${index}`);
        for (let col = 0; col < values.length; col++) {
          const actual = values[col];
          if (actual !== expectedBlock(row, col)) {
            throw new Error(
              `block ${row}, instruction ${index}, ${blockNames[col]}: expected 0x${expectedBlock(row, col).toString(16)}, got 0x${actual.toString(16)} at 0x${address.toString(16)}`,
            );
          }
        }
        blockIndex++;
      }
      if (index >= regTraceLo && index < regTraceHi) {
        console.log(
          `#${index} rip=0x${address.toString(16)} gprs=${engine
            .gprs()
            .map((value) => value.toString(16))
            .join(',')}`,
        );
      }
      instructionIndex++;
    }
    if (address >= SHIM_BASE && address < SHIM_BASE + SHIM_CODE_SIZE) prevHook(address, size);
  };
if (!benchmark) engine.addCodeHook(0x100000000000, 0x100100000000 - 1);
let lastStepHooked = false;
if (!benchmark)
  engine.onPostStep = (address, size) => {
    if (lastStepHooked) tsPrevEnd = address + size;
    lastStepHooked = false;
  };

const ctx = meta.context;
const dsid = meta.dsid;
const ptrField = 0x300000000000; // scratch cursor was reset; ptrField then lenField
const lenField = ptrField + 16;
function invoke(f, args) {
  const regs = [X86_REG.RDI, X86_REG.RSI, X86_REG.RDX, X86_REG.RCX, X86_REG.R8, X86_REG.R9];
  for (let i = 0; i < 6; i++) engine.regWrite(regs[i], args[i] ?? 0);
  const extra = Math.max(args.length - 6, 0);
  let sp = STACK_END - (extra + 1) * 8;
  if (sp % 16 !== 8) sp -= 8;
  const wr64 = (address, value) => {
    const d = new Uint8Array(8);
    new DataView(d.buffer).setBigUint64(0, BigInt(value), true);
    engine.memWrite(address, d);
  };
  wr64(sp, RETURN_ADDRESS);
  for (let i = 0; i < extra; i++) wr64(sp + 8 + i * 8, args[6 + i]);
  engine.regWrite(X86_REG.RSP, sp);
  services.resetFault();
  try {
    engine.emuStart(f, RETURN_ADDRESS);
  } catch (error) {
    if (services.fault) throw services.fault;
    throw error;
  }
  if (services.fault) throw services.fault;
  return engine.regRead(X86_REG.RAX);
}
const readUint64 = (address) => Number(new DataView(engine.memRead(address, 8).buffer).getBigUint64(0, true));

const WATCH_LO = Number(process.env.WATCH_LO ?? '0');
const WATCH_HI = Number(process.env.WATCH_HI ?? '0');
if (WATCH_HI > WATCH_LO) engine.watchRange(WATCH_LO, WATCH_HI);
console.log(`replaying: entry=0x${meta.entry.toString(16)} ctx=0x${ctx.toString(16)} dsid=${dsid}`);
const t0 = performance.now();
tracing = true;
let status;
let fault = null;
try {
  status = invoke(meta.entry, [ctx, dsid, 0, 1, ptrField, lenField]);
} catch (error) {
  fault = error;
}
tracing = false;
console.log(
  `replay finished in ${(performance.now() - t0).toFixed(2)}ms${benchmark ? ' (output/memory benchmark)' : `, ${instructionIndex} instructions (expected ${traceLen})`}`,
);
if (fault) {
  console.log(`FAULT: ${fault.message}`);
}

if (!benchmark) {
  console.log(`BLOCK REGISTERS: ${blockIndex}/${blockRows} rows matched (f64 capture precision)`);
  console.log(`SEQUENCE: ${instructionIndex}/${traceLen} instruction addresses matched`);
}

if (WATCH_HI > WATCH_LO) {
  console.log(`WATCH writes to [0x${WATCH_LO.toString(16)}, 0x${WATCH_HI.toString(16)}): ${engine.watchLog.length}`);
  for (const w of engine.watchLog.slice(0, 40)) {
    console.log(
      `  rip=0x${w.rip.toString(16)} addr=0x${w.address.toString(16)} <- 0x${(w.value >>> 0).toString(16)} (${w.size}B)`,
    );
  }
}
if (fault) throw fault;
if (!benchmark) {
  assert.equal(instructionIndex, traceLen, 'instruction trace ended early');
  assert.equal(blockIndex, blockRows, 'block trace ended early');
}
assert.equal(rdtscValues.length, 0, 'unused RDTSC values');
assert.equal(toInt32(status), 0, 'kbsync status');
const outPtr = readUint64(ptrField);
const outLen = readUint64(lenField);
assert.equal(outLen, expectedOutput.length, 'output length');
assert.deepEqual(engine.memRead(outPtr, outLen), expectedOutput, 'output bytes');
console.log(`OUTPUT: identical (${outLen} bytes)`);
invoke(meta.dispose, [outPtr]);

const expectedShims = JSON.parse(readFileSync(`${DIR}/shims-after.json`, 'utf8'));
assert.deepEqual(
  {
    heapCursor: services.heapCursor,
    allocations: [...services.allocations.entries()],
    freeBlocks: services.freeBlocks,
    iterator: services.iterator,
    icxsOffset: services.icxsOffset,
    lcgState,
  },
  expectedShims,
  'post-dispose shim state',
);

// ---- memory diff ----
let totalChanged = 0;
const regionChanges = [];
for (const r of meta.regions) {
  // The legacy capture omits callee-saved entry registers, whose saved stack slots can differ.
  if (r.name === 'stack') continue;
  const post = new Uint8Array(readFileSync(`${DIR}/post-${r.name}.bin`));
  const now = engine.memRead(r.address, r.size);
  let changed = 0;
  let firstAt = -1;
  for (let i = 0; i < r.size; i++) {
    if (post[i] !== now[i]) {
      changed++;
      if (firstAt < 0) firstAt = i;
    }
  }
  if (changed) regionChanges.push({ name: r.name, changed, firstAt });
  totalChanged += changed;
}
console.log(`MEMORY (vs unicorn post-run): ${totalChanged === 0 ? 'identical ✓' : `${totalChanged} bytes differ`}`);
for (const c of regionChanges) console.log(`  ${c.name}: ${c.changed}B, first at +0x${c.firstAt.toString(16)}`);

assert.equal(totalChanged, 0, 'post-dispose non-stack memory');
if (engine.jit) {
  assert(engine.jit.compiledInstructions > 0, 'replay must execute compiled blocks');
  console.log(`JIT: ${engine.jit.compiledInstructions} compiled, ${engine.jit.fallbackInstructions} interpreted`);
}
