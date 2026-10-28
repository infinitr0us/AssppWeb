// Unicorn-side capture for differential replay validation of the TS engine.
// Produces: full post-init memory (all regions incl. stack), entry registers,
// per-instruction trace, rdtsc results, deterministic shim state, output.
// Run: KBSYNC_ASSET_DIR=<dir> npx tsx tests/kbsync/kbsync-replay-capture.mjs
// Requires KBSYNC_UNICORN_DIR pointing to the external reference engine.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { X86_REG } from '../../src/apple/kbsync/engine.ts';
import { openUnicornReference } from './unicorn-reference.mjs';
import { MachImage } from '../../src/apple/kbsync/machImage.ts';
import { Shims, HEAP_BASE, HEAP_SIZE } from '../../src/apple/kbsync/shims.ts';
import { hardwareBlock, toInt32 } from '../../src/apple/kbsync/machine.ts';

const OUT_DIR = process.env.TRACE_OUT ?? '/tmp/asspp-sap/replay';
const DSID = Number(process.argv[2] ?? 12345678901);

const RETURN_ADDRESS = 0x0000000100000000;
const CORE_FP_BASE = 0x100000000000;
const COMMERCE_BASE = 0x1000400000000;
const KIT_BASE = 0x1000800000000;
const AGENT_BASE = 0x1000c0000000;
const SCRATCH_BASE = 0x0000300000000000;
const SCRATCH_SIZE = 32 << 20;
const STACK_BASE = 0x0000500000000000;
const STACK_SIZE = 8 << 20;
const STACK_END = STACK_BASE + STACK_SIZE;
const PAGE_SIZE = 0x1000;
const STORE_AGENT_GLOBAL_INIT = AGENT_BASE + 0x0c5fc0;
const STORE_AGENT_KBSYNC_ENTRY = AGENT_BASE + 0x0c93c0;
const SC_INFO_PATH = '/Users/Shared/SC Info';
const TIMEOUT_US = 5 * 60 * 1000 * 1000;

const CORE_EXPORT_NAMES = [
  '_WIn9UJ86JKdV4dM',
  '_X46O5IeS',
  '_YlCJ3lg',
  '_dku592fbFAj',
  '_fdjkDSAFjklaf2s',
  '_lxpgvVMLd0S7uRl',
];
const KIT_EXPORT_NAMES = ['_cp2g1b9ro', '_Mib5yocT', '_Fc3vhtJDvr', '_IPaI1oem5iL', '_jEHf8Xzsv8K'];
const ZERO_RETURN_ALIASES = [
  '_pthread_rwlock_rdlock',
  '_pthread_rwlock_rdlock$UNIX2003',
  '_pthread_mutex_init',
  '_pthread_mutex_destroy',
  '_pthread_rwlock_destroy',
];

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
const hardwareID = Uint8Array.from([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]);

// rdtsc sites (from the per-block disassembly of executed blocks)
const rdtscSites = new Set();
for (const [file, emuBase, vmaBase] of [
  ['/tmp/asspp-sap/blocks2-CoreFP.asm', CORE_FP_BASE, 0],
  ['/tmp/asspp-sap/blocks2-storeagent.asm', AGENT_BASE, 0x100000000],
]) {
  try {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/^; ===== (\S+)\+0x([0-9a-f]+)/gm)) {
      const img = m[1],
        off = parseInt(m[2], 16);
      const base = img === 'CoreFP' ? CORE_FP_BASE : img === 'storeagent' ? AGENT_BASE : null;
      if (base === null) continue;
      // per-block: find rdtsc lines inside this block section
      const section = text.slice(m.index, text.indexOf('\n; =====', m.index + 1));
      if (/\brdtsc\b/.test(section)) rdtscSites.add(base + off);
    }
  } catch {}
}
console.log(`rdtsc block-entry sites: ${rdtscSites.size}`);

// deterministic randomness (shared contract with the TS replay)
let lcgState = 0x12345678;
function lcgNext() {
  lcgState = (Math.imul(lcgState, 1103515245) + 12345) & 0x7fffffff;
  return lcgState >>> 0;
}
const FIXED_NOW_MS = 1700000000123;

const engine = await openUnicornReference();
const regions = [];
const memMap = (address, size, name) => {
  engine.memMap(address, size);
  regions.push({ address, size, name });
};
memMap(RETURN_ADDRESS, PAGE_SIZE, 'return');
memMap(SCRATCH_BASE, SCRATCH_SIZE, 'scratch');
memMap(HEAP_BASE, HEAP_SIZE, 'heap');
memMap(STACK_BASE, STACK_SIZE, 'stack');
engine.memWrite(RETURN_ADDRESS, new Uint8Array([0xf4]));

const imageSpecs = [
  { name: 'CoreFP', data: assets.coreFP, base: CORE_FP_BASE },
  { name: 'CommerceCore', data: assets.commerceCore, base: COMMERCE_BASE },
  { name: 'CommerceKit', data: assets.commerceKit, base: KIT_BASE },
  { name: 'storeagent', data: assets.storeAgent, base: AGENT_BASE },
];
const images = new Map(imageSpecs.map((s) => [s.name, MachImage.open(s.name, s.data)]));
const exportsMap = new Map();
const coreExports = {};
for (const name of CORE_EXPORT_NAMES) {
  const a = images.get('CoreFP').export(name, CORE_FP_BASE);
  exportsMap.set(name, a);
  coreExports[name] = a;
}
exportsMap.set('_get_mac_address', images.get('CommerceCore').export('_get_mac_address', COMMERCE_BASE));
for (const name of KIT_EXPORT_NAMES) exportsMap.set(name, images.get('CommerceKit').export(name, KIT_BASE));

const services = await Shims.open(engine, coreExports, assets.coreFPICXS, { zeroReturnAliases: ZERO_RETURN_ALIASES });
const resolver = (name) => exportsMap.get(name) ?? services.resolve(name);
for (const spec of imageSpecs) {
  const image = images.get(spec.name);
  image.relocate(spec.base, resolver);
  image.load({ memMap: (a, s) => memMap(a, s, spec.name), memWrite: (a, d) => engine.memWrite(a, d) });
}
const dispose = exportsMap.get('_jEHf8Xzsv8K');

// hooks registered BEFORE init: the patched TCI build does not re-check
// code hooks for blocks translated earlier, so late registration would
// silently skip init-translated blocks (observed with the import resolver).
const SHIM_BASE = 0x0000200000000000;
const SHIM_CODE_SIZE = 0x80000;
const prevHook = engine.onCodeHook;
const trace = [];
const rdtscVals = []; // [rax, rdx] per executed rdtsc
let tracing = false;
let pendingRdtsc = false;
const BLOCK_REG_IDS = [
  X86_REG.RAX,
  X86_REG.RCX,
  X86_REG.RDX,
  X86_REG.RSI,
  X86_REG.RDI,
  X86_REG.R8,
  X86_REG.R9,
  X86_REG.R11,
];
const blockRegs = [];
let prevEnd = -1;
engine.onCodeHook = (address, size) => {
  if (tracing) {
    if (address !== prevEnd) {
      const row = [address];
      for (const id of BLOCK_REG_IDS) row.push(engine.regRead(id));
      blockRegs.push(row);
    }
    prevEnd = address + size;
    trace.push(address);
    if (pendingRdtsc) {
      pendingRdtsc = false;
      rdtscVals.push(engine.regRead(X86_REG.RAX), engine.regRead(X86_REG.RDX));
    }
    {
      const b = engine.memRead(address, 2);
      if (b[0] === 0x0f && b[1] === 0x31) pendingRdtsc = true;
    }
  }
  if (address >= SHIM_BASE && address < SHIM_BASE + SHIM_CODE_SIZE) prevHook(address, size);
};
engine.addCodeHook(0x100000000000, 0x100100000000 - 1);

// ---- deterministic shim overrides (arc4random / gettimeofday) ----
const detHandlers = services.handlers; // runtime access to private field
const detEntries = services.entries;
const detSymbols = services.symbols;
function overrideShim(name, fn) {
  const addr = detSymbols.get(name);
  if (!addr) throw new Error(`shim ${name} missing`);
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

function align(v, a) {
  return Math.floor((v + a - 1) / a) * a;
}
let scratchCursor = 0;
const scratch = (data) => {
  const isData = typeof data !== 'number';
  const size = isData ? data.length : data;
  const reserved = align(Math.max(size, 1), 16);
  const address = SCRATCH_BASE + scratchCursor;
  scratchCursor += reserved;
  if (size !== 0) engine.memWrite(address, isData ? data : new Uint8Array(size));
  return address;
};

function invoke(f, args, timeoutUs = TIMEOUT_US) {
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
    engine.emuStart(f, RETURN_ADDRESS, timeoutUs, 0);
  } catch (error) {
    if (services.fault) throw services.fault;
    throw error;
  }
  if (services.fault) throw services.fault;
  return engine.regRead(X86_REG.RAX);
}
const readUint32 = (address) => new DataView(engine.memRead(address, 4).buffer).getUint32(0, true);
const readUint64 = (address) => Number(new DataView(engine.memRead(address, 8).buffer).getBigUint64(0, true));

// ---- phase 1: init ----
console.log('init...');
let t0 = Date.now();
const hardware = hardwareBlock(hardwareID);
const hwAddr = scratch(hardware);
const pathAddr = scratch(new TextEncoder().encode(`${SC_INFO_PATH}\0`));
const ctxField = scratch(4);
scratchCursor = 0;
const st = invoke(STORE_AGENT_GLOBAL_INIT, [0, hwAddr, pathAddr, ctxField]);
if (toInt32(st) !== 0) throw new Error(`init returned ${toInt32(st)}`);
const context = readUint32(ctxField);
console.log(`init ok ${((Date.now() - t0) / 1000).toFixed(0)}s context=0x${context.toString(16)}`);
engine.memWrite(SCRATCH_BASE, new Uint8Array(SCRATCH_SIZE));
scratchCursor = 0;

// ---- serialize shims + memory ----
mkdirSync(OUT_DIR, { recursive: true });
const shimsState = {
  symbols: [...detSymbols.entries()],
  entries: [...detEntries.entries()],
  codeCursor: services.codeCursor,
  dataCursor: services.dataCursor,
  epilogue: services.epilogue,
  errnoAddress: services.errnoAddress,
  heapCursor: services.heapCursor,
  allocations: [...services.allocations.entries()],
  freeBlocks: services.freeBlocks,
  iterator: services.iterator,
  icxsOffset: services.icxsOffset,
};
writeFileSync(`${OUT_DIR}/shims.json`, JSON.stringify(shimsState));
for (const r of regions) {
  writeFileSync(`${OUT_DIR}/mem-${r.name}.bin`, Buffer.from(engine.memRead(r.address, r.size)));
}
writeFileSync(
  `${OUT_DIR}/meta.json`,
  JSON.stringify({
    dsid: DSID,
    context,
    regions: regions.map(({ address, size, name }) => ({ address, size, name })),
    exports: [...exportsMap.entries()],
    entry: STORE_AGENT_KBSYNC_ENTRY,
    dispose,
    lcgStateAfterInit: lcgState,
    fixedNow: FIXED_NOW_MS,
  }),
);

// ---- phase 2: trace final call + rdtsc capture ----
const ptrField = scratch(8);
const lenField = scratch(8);
const preEntryRegs = {
  rax: engine.regRead(X86_REG.RAX),
  rcx: engine.regRead(X86_REG.RCX),
  rdx: engine.regRead(X86_REG.RDX),
  rsi: engine.regRead(X86_REG.RSI),
  rdi: engine.regRead(X86_REG.RDI),
  r8: engine.regRead(X86_REG.R8),
  r9: engine.regRead(X86_REG.R9),
  r11: engine.regRead(X86_REG.R11),
};
t0 = Date.now();
tracing = true;
const kst = invoke(STORE_AGENT_KBSYNC_ENTRY, [context, DSID, 0, 1, ptrField, lenField]);
tracing = false;
console.log(
  `kbsync: ${((Date.now() - t0) / 1000).toFixed(1)}s, ${trace.length} insns, ${rdtscVals.length / 2} rdtsc, status=${toInt32(kst)}`,
);

const outPtr = readUint64(ptrField);
const outLen = readUint64(lenField);
const output = engine.memRead(outPtr, outLen);
console.log(`output ${outLen}B: ${Buffer.from(output).toString('hex').slice(0, 48)}...`);
invoke(dispose, [outPtr]);

writeFileSync(`${OUT_DIR}/trace.f64`, Buffer.from(new Float64Array(trace).buffer));
writeFileSync(`${OUT_DIR}/blockregs.f64`, Buffer.from(new Float64Array(blockRegs.flat()).buffer));
writeFileSync(`${OUT_DIR}/rdtsc.json`, JSON.stringify(rdtscVals));
writeFileSync(`${OUT_DIR}/entry-regs.json`, JSON.stringify(preEntryRegs));
writeFileSync(`${OUT_DIR}/output.bin`, Buffer.from(output));
// post-call memory for write comparison
for (const r of regions) {
  writeFileSync(`${OUT_DIR}/post-${r.name}.bin`, Buffer.from(engine.memRead(r.address, r.size)));
}
const shimsAfter = {
  heapCursor: services.heapCursor,
  allocations: [...services.allocations.entries()],
  freeBlocks: services.freeBlocks,
  iterator: services.iterator,
  icxsOffset: services.icxsOffset,
  lcgState,
};
writeFileSync(`${OUT_DIR}/shims-after.json`, JSON.stringify(shimsAfter));
console.log(`capture complete -> ${OUT_DIR}`);
process.exit(0);
