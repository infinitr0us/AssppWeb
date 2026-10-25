// Research harness: runs the StoreAgent kbsync flow with a full instruction
// trace of the final kbsync call, plus guest-memory snapshots before/after.
// Run: KBSYNC_ASSET_DIR=<dir> npx tsx tests/kbsync/kbsync-trace.mjs [dsid]
// Requires KBSYNC_UNICORN_DIR pointing to the external reference engine.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { X86_REG } from '../../src/apple/kbsync/engine.ts';
import { openUnicornReference } from './unicorn-reference.mjs';
import { MachImage } from '../../src/apple/kbsync/machImage.ts';
import { Shims, HEAP_BASE, HEAP_SIZE } from '../../src/apple/kbsync/shims.ts';
import { hardwareBlock, toInt32 } from '../../src/apple/kbsync/machine.ts';

const OUT_DIR = process.env.TRACE_OUT ?? '/tmp/asspp-sap/trace';
const DSID = Number(process.argv[2] ?? 12345678901);

const RETURN_ADDRESS = 0x0000000100000000;
const CORE_FP_BASE = 0x0000100000000000;
const COMMERCE_BASE = 0x0000100040000000;
const KIT_BASE = 0x0000100080000000;
const AGENT_BASE = 0x00001000c0000000;
const SCRATCH_BASE = 0x0000300000000000;
const SCRATCH_SIZE = 32 << 20;
const STACK_BASE = 0x0000500000000000;
const STACK_SIZE = 8 << 20;
const STACK_END = STACK_BASE + STACK_SIZE;
const PAGE_SIZE = 0x1000;
const STORE_AGENT_GLOBAL_INIT = AGENT_BASE + 0x0c5fc0;
const STORE_AGENT_KBSYNC_ENTRY = AGENT_BASE + 0x0c93c0;
const SC_INFO_PATH = '/Users/Shared/SC Info';
const DISPOSE = '_jEHf8Xzsv8K';
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
const hardwareID = Uint8Array.from((process.env.TRACE_HW ?? '0a1b2c3d4e5f').match(/../g).map((b) => parseInt(b, 16)));

const regions = []; // {address,size,name} for snapshotting
const imageSpans = []; // {base, span, name}

function align(v, a) {
  return Math.floor((v + a - 1) / a) * a;
}

// ---- open the machine (mirrors GuestMachine.open) ----
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
for (const spec of imageSpecs) {
  const image = images.get(spec.name);
  image.relocate(spec.base, resolver);
  image.load({
    memMap: (address, size) => memMap(address, size, spec.name),
    memWrite: (address, data) => engine.memWrite(address, data),
  });
  imageSpans.push({ base: spec.base, span: 0, name: spec.name });
}
const dispose = exportsMap.get(DISPOSE);

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
  for (let i = 0; i < regs.length; i++) engine.regWrite(regs[i], args[i] ?? 0);
  const extra = Math.max(args.length - regs.length, 0);
  let sp = STACK_END - (extra + 1) * 8;
  if (sp % 16 !== 8) sp -= 8;
  const wr64 = (address, value) => {
    const d = new Uint8Array(8);
    new DataView(d.buffer).setBigUint64(0, BigInt(value), true);
    engine.memWrite(address, d);
  };
  wr64(sp, RETURN_ADDRESS);
  for (let i = 0; i < extra; i++) wr64(sp + 8 + i * 8, args[regs.length + i]);
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

function snapshot(label) {
  const out = {};
  for (const r of regions) {
    if (r.name === 'stack') continue; // transient
    out[r.name] = engine.memRead(r.address, r.size);
  }
  return out;
}

function diffRegions(a, b, label) {
  const changes = [];
  for (const key of Object.keys(a)) {
    const ra = a[key];
    const rb = b[key];
    if (ra.length !== rb.length) continue;
    const region = regions.find((r) => r.name === key);
    let runStart = -1;
    for (let i = 0; i <= ra.length; i += 16) {
      const sliceEnd = Math.min(i + 16, ra.length);
      let differs = false;
      if (sliceEnd === ra.length) differs = true;
      else
        for (let j = i; j < i + 16; j++) {
          if (ra[j] !== rb[j]) {
            differs = true;
            break;
          }
        }
      const isLast = i >= ra.length;
      if (!isLast && differs && runStart < 0) runStart = i;
      if (differs && runStart >= 0 && (isLast || true) && (isLast || !differsNext(ra, rb, i + 16))) {
        // simplified below
      }
    }
    // simpler: collect changed 16-byte blocks
    let blocks = [];
    for (let i = 0; i < ra.length; i += 16) {
      let d = false;
      for (let j = i; j < Math.min(i + 16, ra.length); j++) {
        if (ra[j] !== rb[j]) {
          d = true;
          break;
        }
      }
      if (d) blocks.push(i);
    }
    if (blocks.length) {
      // merge contiguous block runs
      let runs = [];
      let s = blocks[0],
        p = blocks[0];
      for (let k = 1; k <= blocks.length; k++) {
        const cur = blocks[k];
        if (cur !== undefined && cur === p + 16) {
          p = cur;
          continue;
        }
        runs.push([region.address + s, region.address + p + 16]);
        s = cur;
        p = cur;
      }
      for (const [start, end] of runs)
        changes.push({ region: key, start: start.toString(16), end: end.toString(16), bytes: end - start });
    }
  }
  console.log(`[${label}] changed regions: ${changes.length}`);
  for (const c of changes.slice(0, 60)) console.log(`  ${c.region} 0x${c.start}..0x${c.end} (${c.bytes}B)`);
  if (changes.length > 60) console.log(`  ... +${changes.length - 60} more`);
  return changes;
}
const differsNext = () => false;

// ---- phase 1: global init (untraced) ----
console.log(`phase1: global init (dsid=${DSID})...`);
let t0 = Date.now();
const hardware = hardwareBlock(hardwareID);
const hwAddr = scratch(hardware);
const pathAddr = scratch(new TextEncoder().encode(`${SC_INFO_PATH}\0`));
const ctxField = scratch(4);
scratchCursor = 0;
let st = invoke(STORE_AGENT_GLOBAL_INIT, [0, hwAddr, pathAddr, ctxField]);
if (toInt32(st) !== 0) throw new Error(`init returned ${toInt32(st)}`);
const globalContext = readUint32(ctxField);
console.log(`init ok in ${Date.now() - t0}ms, context=0x${globalContext.toString(16)}`);
if (process.env.TRACE_INIT_ONLY) {
  const pre2 = snapshot('init');
  mkdirSync(OUT_DIR, { recursive: true });
  for (const [n, d] of Object.entries(pre2)) writeFileSync(`${OUT_DIR}/init-${n}.bin`, Buffer.from(d));
  writeFileSync(`${OUT_DIR}/context.txt`, String(globalContext));
  console.log('init-only snapshots written');
  process.exit(0);
}
engine.memWrite(SCRATCH_BASE, new Uint8Array(SCRATCH_SIZE)); // clear scratch
scratchCursor = 0;

// ---- phase 2: snapshot pre-kbsync ----
const pre = snapshot('pre');

// ---- phase 3: trace the kbsync call ----
console.log('phase3: tracing kbsync call...');
const SHIM_BASE = 0x0000200000000000;
const SHIM_CODE_SIZE = 0x80000;
const prevHook = engine.onCodeHook;
const trace = [];
let tracing = false;
engine.onCodeHook = (address, size) => {
  if (tracing) trace.push(address);
  if (address >= SHIM_BASE && address < SHIM_BASE + SHIM_CODE_SIZE) prevHook(address, size);
};
engine.addCodeHook(0x0000100000000000, 0x0000101000000000); // all image code

t0 = Date.now();
tracing = true;
const ptrField = scratch(8);
const lenField = scratch(8);
st = invoke(STORE_AGENT_KBSYNC_ENTRY, [globalContext, DSID, 0, 1, ptrField, lenField]);
tracing = false;
console.log(
  `kbsync call: ${((Date.now() - t0) / 1000).toFixed(1)}s wall, ${trace.length} instructions traced, status=${toInt32(st)}`,
);

const outPtr = readUint64(ptrField);
const outLen = readUint64(lenField);
const output = engine.memRead(outPtr, outLen);
console.log(
  `output: ${outLen} bytes @0x${outPtr.toString(16)}: ${Buffer.from(output).toString('hex').slice(0, 64)}...`,
);
invoke(dispose, [outPtr]);

// ---- phase 4: snapshot post-kbsync + save artifacts ----
const post = snapshot('post');
mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(`${OUT_DIR}/trace.f64`, Buffer.from(new Float64Array(trace).buffer));
writeFileSync(`${OUT_DIR}/output-${DSID}.bin`, Buffer.from(output));
for (const [name, data] of Object.entries(pre)) {
  writeFileSync(`${OUT_DIR}/pre-${name}.bin`, Buffer.from(data));
  writeFileSync(`${OUT_DIR}/post-${name}.bin`, Buffer.from(post[name]));
}
console.log(`artifacts written to ${OUT_DIR}`);

diffRegions(pre, post, 'kbsync-call state delta');

// quick histogram: which 4K pages executed
const pages = new Map();
for (const a of trace) {
  const p = Math.floor(a / 0x1000);
  pages.set(p, (pages.get(p) ?? 0) + 1);
}
const sorted = [...pages.entries()].sort((x, y) => y[1] - x[1]);
console.log(`\ndistinct 4K pages executed: ${sorted.length}`);
const label = (page) => {
  const base = page * 0x1000;
  for (const spec of imageSpecs) {
    if (base >= spec.base && base < spec.base + 0x2000000) return `${spec.name}+0x${(base - spec.base).toString(16)}`;
  }
  if (base >= SHIM_BASE) return `shim+0x${(base - SHIM_BASE).toString(16)}`;
  return `0x${base.toString(16)}`;
};
for (const [page, count] of sorted.slice(0, 40)) {
  console.log(`  ${label(page).padEnd(28)} ${String(count).padStart(9)} insns`);
}
engine.close?.();
services.close?.();
process.exit(0);
