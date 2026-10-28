// Init profiler: counts init instructions per page, collects distinct branch
// targets via bitmaps, and snapshots guest memory at CoreFP export boundaries.
// Requires KBSYNC_UNICORN_DIR pointing to the external reference engine.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { X86_REG } from '../../src/apple/kbsync/engine.ts';
import { openUnicornReference } from './unicorn-reference.mjs';
import { MachImage } from '../../src/apple/kbsync/machImage.ts';
import { Shims, HEAP_BASE, HEAP_SIZE } from '../../src/apple/kbsync/shims.ts';
import { hardwareBlock, toInt32 } from '../../src/apple/kbsync/machine.ts';

const OUT_DIR = process.env.TRACE_OUT ?? '/tmp/asspp-sap/initprof';
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
const SC_INFO_PATH = '/Users/Shared/SC Info';
const TIMEOUT_US = 30 * 60 * 1000 * 1000;

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
const hardwareID = Uint8Array.from((process.env.TRACE_HW ?? '0a1b2c3d4e5f').match(/../g).map((b) => parseInt(b, 16)));

const regions = [];
const engine = await openUnicornReference();
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
const imageSizes = new Map();
for (const spec of imageSpecs) {
  const image = images.get(spec.name);
  image.relocate(spec.base, resolver);
  let span = 0;
  image.load({
    memMap: (address, size) => {
      memMap(address, size, spec.name);
      span = Math.max(span, address + size - spec.base);
    },
    memWrite: (address, data) => engine.memWrite(address, data),
  });
  imageSizes.set(spec.name, span);
}
mkdirSync(OUT_DIR, { recursive: true });

// ---- profiling state (typed arrays only, no Map/Set in the hot path) ----
const IMG_LO = CORE_FP_BASE;
const IMG_HI = AGENT_BASE + 0x4000000;
const pageCounts = new Uint32Array(1 << 20); // (addr - IMG_LO) >> 12
const targetBitmap = new Uint8Array(((IMG_HI - IMG_LO) / 8) | 0);
let totalCount = 0;
let prevEnd = -1;
let profiling = false;
function markTarget(off) {
  targetBitmap[off >> 3] |= 1 << (off & 7);
}

// export-boundary snapshots
const phaseSnaps = [];
const coreEntries = new Map(Object.entries(coreExports).map(([n, a]) => [a, n]));
let phaseCounter = 0;

const SHIM_BASE = 0x0000200000000000;
const SHIM_CODE_SIZE = 0x80000;
const prevHook = engine.onCodeHook;
engine.onCodeHook = (address, size) => {
  if (profiling) {
    totalCount++;
    const off = address - IMG_LO;
    if (off >= 0 && off < 0x10000000000) {
      pageCounts[off >> 12]++;
      if (address !== prevEnd) markTarget(off);
      prevEnd = address + size;
    } else {
      prevEnd = -1;
    }
  }
  const name = coreEntries.get(address);
  if (name && phaseCounter < 60) {
    phaseCounter++;
    const snap = {
      phase: phaseCounter,
      entry: name,
      coreFP: engine.memRead(CORE_FP_BASE, imageSizes.get('CoreFP')),
      heapUsed: services['heapCursor'] ?? 0,
      t: Date.now(),
    };
    phaseSnaps.push(snap);
    writeFileSync(`${OUT_DIR}/phase-${String(phaseCounter).padStart(2, '0')}-${name}.bin`, Buffer.from(snap.coreFP));
    console.log(`phase ${phaseCounter}: entered ${name} (t=${snap.t})`);
  }
  if (address >= SHIM_BASE && address < SHIM_BASE + SHIM_CODE_SIZE) prevHook(address, size);
};
engine.attachCodeHook();
engine.addCodeHook(IMG_LO, IMG_HI - 1);
const t0 = Date.now();
engine.onCodeHook; // ensure set before Shims? (Shims.open already set; we wrapped after)

// ---- invoke helper ----
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
  profiling = true;
  prevEnd = -1;
  try {
    engine.emuStart(f, RETURN_ADDRESS, timeoutUs, 0);
  } catch (error) {
    profiling = false;
    if (services.fault) throw services.fault;
    throw error;
  }
  profiling = false;
  if (services.fault) throw services.fault;
  return engine.regRead(X86_REG.RAX);
}
const readUint32 = (address) => new DataView(engine.memRead(address, 4).buffer).getUint32(0, true);

// ---- run init under profiling ----
console.log('profiling global init...');
const hardware = hardwareBlock(hardwareID);
const hwAddr = scratch(hardware);
const pathAddr = scratch(new TextEncoder().encode(`${SC_INFO_PATH}\0`));
const ctxField = scratch(4);
scratchCursor = 0;
const st = invoke(STORE_AGENT_GLOBAL_INIT, [0, hwAddr, pathAddr, ctxField]);
if (toInt32(st) !== 0) throw new Error(`init returned ${toInt32(st)}`);
const context = readUint32(ctxField);
console.log(`init done in ${(Date.now() - t0) / 1000}s: total insns=${totalCount.toLocaleString()}`);

let distinctTargets = 0;
for (const byte of targetBitmap) {
  let v = byte;
  while (v) {
    distinctTargets += v & 1;
    v >>= 1;
  }
}
console.log(`distinct branch-target addresses (≈unique blocks): ${distinctTargets}`);

// page histogram
const pages = [];
for (let i = 0; i < pageCounts.length; i++) if (pageCounts[i]) pages.push([i, pageCounts[i]]);
pages.sort((a, b) => b[1] - a[1]);
console.log(`pages executed: ${pages.length}`);
const label = (page) => {
  const base = IMG_LO + page * 0x1000;
  for (const spec of imageSpecs)
    if (base >= spec.base && base < spec.base + 0x4000000) return `${spec.name}+0x${(base - spec.base).toString(16)}`;
  return `0x${base.toString(16)}`;
};
for (let i = 0; i < Math.min(30, pages.length); i++)
  console.log(`  ${label(pages[i][0]).padEnd(24)} ${String(pages[i][1]).padStart(13)}`);
writeFileSync(`${OUT_DIR}/targets.bmp`, Buffer.from(targetBitmap));
writeFileSync(`${OUT_DIR}/pages.u32`, Buffer.from(pageCounts.buffer));
writeFileSync(
  `${OUT_DIR}/summary.json`,
  JSON.stringify(
    {
      totalInsns: totalCount,
      distinctTargets,
      pages: pages.map(([p, c]) => [label(p), c]),
      context,
    },
    null,
    2,
  ),
);
console.log('summary written');
process.exit(0);
