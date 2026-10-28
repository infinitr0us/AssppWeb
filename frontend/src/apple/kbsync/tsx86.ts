// Pure-TypeScript x86-64 interpreter for the kbsync guest (StoreAgent/CoreFP).
//
// This experimental engine covers the integer and vector instructions observed
// in StoreAgent kbsync traces (see docs/kbsync-reverse-engineering.md), with
// the same method surface as the vendored Unicorn wasm glue, so machImage.ts
// and shims.ts run unchanged on top of it.
//
// Memory: a short list of contiguous regions with a one-entry lookup cache.
// Registers: 32-bit low/high halves; qword data operations use BigInt.
// Effective addresses convert to Number only after modulo-width arithmetic.

import { X86JitCompiler } from './tsx86-jit';
import type { JitBlock, JitLink, MemorySite } from './tsx86-jit';

export const X86_REG = {
  RAX: 35,
  RCX: 38,
  RDI: 39,
  RDX: 40,
  RIP: 41,
  RSI: 43,
  RSP: 44,
  R8: 106,
  R9: 107,
  R11: 109,
} as const;

// Internal register file order.
const RAX = 0,
  RCX = 1,
  RDX = 2,
  RBX = 3,
  RSP = 4,
  RBP = 5,
  RSI = 6,
  RDI = 7;
const R8 = 8,
  R9 = 9,
  R10 = 10,
  R11 = 11,
  R12 = 12,
  R13 = 13,
  R14 = 14,
  R15 = 15;

const REG_BY_ID = new Map<number, number>([
  [X86_REG.RAX, RAX],
  [X86_REG.RCX, RCX],
  [X86_REG.RDI, RDI],
  [X86_REG.RDX, RDX],
  [X86_REG.RIP, -1],
  [X86_REG.RSI, RSI],
  [X86_REG.RSP, RSP],
  [X86_REG.R8, R8],
  [X86_REG.R9, R9],
  [X86_REG.R11, R11],
]);

interface Region {
  base: number;
  end: number;
  bytes: Uint8Array;
  view: DataView;
}

const F64_BUF = new Float64Array(1);
const F32_BUF = new Float32Array(1);
const U32_BUF = new Uint32Array(F64_BUF.buffer);

function f64bits(v: number): number {
  F64_BUF[0] = v;
  return U32_BUF[0] + U32_BUF[1] * 4294967296;
}
function f32bits(v: number): number {
  F32_BUF[0] = v;
  return new Uint32Array(F32_BUF.buffer)[0];
}
const U64_MASK = 0xffffffffffffffffn;
/** Exact 64-bit AND/OR/XOR on JS numbers via BigInt (values stay below 2^53). */
function logic64(a: number, b: number, op: number): number {
  let x = BigInt(a);
  let y = BigInt(b);
  let r = op === 0 ? x | y : op === 1 ? x & y : x ^ y;
  r &= U64_MASK;
  return Number(r);
}

function truncateInt(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.trunc(v);
}

export class X86Fault extends Error {
  constructor(
    message: string,
    public rip: number,
    readonly opcode: number,
  ) {
    super(`${message} at 0x${rip.toString(16)} (op 0x${opcode.toString(16)})`);
  }
}

export interface X86Options {
  rdtsc?: () => number;
  jit?: boolean;
}

export class TsX86Engine {
  onCodeHook: ((address: number, size: number) => void) | null = null;
  /** Notified after each step with (instructionAddress, instructionSize). */
  onPostStep: ((address: number, size: number) => void) | null = null;
  /** Compiled execution boundary observer used by differential validation. */
  onJitBlock: (() => void) | null = null;

  /** Watchpoints: address -> log of {rip, value, size} on writes. */
  readonly watchLog: { rip: number; address: number; value: number; size: number }[] = [];
  private watchRanges: { lo: number; hi: number }[] = [];
  watchRange(lo: number, hi: number): void {
    this.watchRanges.push({ lo, hi });
  }
  private noteWrite(address: number, value: number, size: number): void {
    this.jit?.invalidate(address, size);
    for (const w of this.watchRanges) {
      if (address >= w.lo && address < w.hi) {
        this.watchLog.push({ rip: this.rip, address, value, size });
        return;
      }
    }
  }

  private readonly lo = new Uint32Array(16);
  private readonly hi = new Uint32Array(16);
  private readonly xmm = Array.from({ length: 16 }, () => new Uint8Array(16));
  private rip = 0;
  private cf = 0;
  private zf = 0;
  private sf = 0;
  private of = 0;
  private pf = 0;
  private af = 0;
  private df = 0;
  private regions: Region[] = [];
  private lastRegion: Region | null = null;
  private hooks: { begin: number; end: number }[] = [];
  private stopRequested = false;
  private insnCount = 0;
  private curRex = 0;
  private tsc = 1;
  private readonly rdtscProvider: (() => number) | null;
  private rdtscQueue: number[] | null = null;
  readonly jit: X86JitCompiler | null;

  constructor(options: X86Options = {}) {
    this.rdtscProvider = options.rdtsc ?? null;
    this.jit = options.jit ? new X86JitCompiler(this) : null;
  }

  /** Replays RDTSC values recorded from a reference run (differential test). */
  replayRdtsc(values: number[] | null): void {
    this.rdtscQueue = values;
  }

  // ---- memory ----

  memMap(address: number, size: number): void {
    this.jit?.clear();
    for (const r of this.regions) {
      if (address < r.end && r.base < address + size) {
        throw new Error(`mem_map overlap at 0x${address.toString(16)}`);
      }
    }
    let base = address;
    let end = address + size;
    let bytes = new Uint8Array(size);
    // Mappings that touch become one region, so every contiguous mapped span has one backing view.
    const touching = this.regions.filter((r) => r.end === address || r.base === end);
    if (touching.length) {
      for (const r of touching) {
        base = Math.min(base, r.base);
        end = Math.max(end, r.end);
      }
      bytes = new Uint8Array(end - base);
      for (const r of touching) bytes.set(r.bytes, r.base - base);
      this.regions = this.regions.filter((r) => !touching.includes(r));
    }
    this.regions.push({ base, end, bytes, view: new DataView(bytes.buffer) });
    this.regions.sort((a, b) => a.base - b.base);
    this.lastRegion = null;
  }

  memUnmap(address: number, size: number): void {
    this.jit?.clear();
    this.regions = this.regions.filter((r) => !(address === r.base && size === r.end - r.base));
    this.lastRegion = null;
  }

  private region(address: number): Region {
    const last = this.lastRegion;
    if (last && address >= last.base && address < last.end) return last;
    for (const r of this.regions) {
      if (address >= r.base && address < r.end) {
        this.lastRegion = r;
        return r;
      }
    }
    throw new X86Fault(`unmapped read at 0x${address.toString(16)}`, this.rip, -1);
  }

  /** Points a compiled memory-site cache at the region containing `address`. */
  refill(site: MemorySite, address: number): void {
    const r = this.region(address);
    site.base = r.base;
    site.end = r.end;
    site.bytes = r.bytes;
    site.view = r.view;
  }

  /** Like refill, for a span of accesses that must all lie in the region containing `address`. */
  refillSpan(site: MemorySite, address: number, length: number): void {
    const r = this.region(address);
    if (address + length > r.end) throw new X86Fault(`unmapped access at 0x${r.end.toString(16)}`, this.rip, -1);
    site.base = r.base;
    site.end = r.end;
    site.bytes = r.bytes;
    site.view = r.view;
  }

  memWrite(address: number, data: Uint8Array): void {
    if (data.length === 0) return;
    this.jit?.invalidate(address, data.length);
    const r = this.region(address);
    const off = address - r.base;
    if (off + data.length > r.bytes.length) {
      throw new X86Fault(`write past region end 0x${address.toString(16)}`, this.rip, -1);
    }
    r.bytes.set(data, off);
  }

  memRead(address: number, length: number): Uint8Array {
    const out = new Uint8Array(length);
    if (length === 0) return out;
    const r = this.region(address);
    const off = address - r.base;
    if (off + length > r.bytes.length) {
      throw new X86Fault(`read past region end 0x${address.toString(16)}`, this.rip, -1);
    }
    out.set(r.bytes.subarray(off, off + length));
    return out;
  }

  read8(a: number): number {
    return this.region(a).bytes[a - this.lastRegion!.base];
  }
  write8(a: number, v: number): void {
    this.noteWrite(a, v, 1);
    this.region(a).bytes[a - this.lastRegion!.base] = v & 0xff;
  }
  read16(a: number): number {
    const r = this.region(a);
    return r.view.getUint16(a - r.base, true);
  }
  write16(a: number, v: number): void {
    this.noteWrite(a, v, 2);
    const r = this.region(a);
    r.view.setUint16(a - r.base, v, true);
  }
  read32(a: number): number {
    const r = this.region(a);
    return r.view.getUint32(a - r.base, true);
  }
  write32(a: number, v: number): void {
    this.noteWrite(a, v, 4);
    const r = this.region(a);
    r.view.setUint32(a - r.base, v, true);
  }
  read64(a: number): number {
    return this.read32(a) + this.read32(a + 4) * 4294967296;
  }
  write64(a: number, v: number): void {
    this.noteWrite(a, v, 8);
    if (v < 0) {
      const hi = Math.floor(v / 4294967296);
      this.write32(a, v - hi * 4294967296);
      this.write32(a + 4, hi);
    } else {
      this.write32(a, v % 4294967296);
      this.write32(a + 4, Math.floor(v / 4294967296));
    }
  }

  private readQword(address: number): bigint {
    return BigInt(this.read32(address)) | (BigInt(this.read32(address + 4)) << 32n);
  }

  private writeQword(address: number, value: bigint): void {
    this.write32(address, Number(value & 0xffffffffn));
    this.write32(address + 4, Number((value >> 32n) & 0xffffffffn));
  }

  private regQword(index: number): bigint {
    return BigInt(this.lo[index]) | (BigInt(this.hi[index]) << 32n);
  }

  private setQword(index: number, value: bigint): void {
    this.lo[index] = Number(value & 0xffffffffn);
    this.hi[index] = Number((value >> 32n) & 0xffffffffn);
  }

  private rmQword(r: { mod: number; rm: number; addr: number }): bigint {
    return r.mod === 3 ? this.regQword(r.rm) : this.readQword(r.addr);
  }

  private setRMQword(r: { mod: number; rm: number; addr: number }, value: bigint): void {
    if (r.mod === 3) this.setQword(r.rm, value);
    else this.writeQword(r.addr, value);
  }

  private aluQword(kind: number, a: bigint, b: bigint): bigint {
    a = BigInt.asUintN(64, a);
    b = BigInt.asUintN(64, b);
    const carry = kind === 2 || kind === 3 ? BigInt(this.cf) : 0n;
    const subtract = kind === 3 || kind === 5 || kind === 7;
    const logical = kind === 1 || kind === 4 || kind === 6;
    const full = logical ? (kind === 1 ? a | b : kind === 4 ? a & b : a ^ b) : subtract ? a - b - carry : a + b + carry;
    const result = BigInt.asUintN(64, full);
    const sign = 1n << 63n;
    this.cf = logical ? 0 : subtract ? Number(a < b + carry) : Number(full > U64_MASK);
    this.of = logical ? 0 : Number(((subtract ? a ^ b : ~(a ^ b)) & (a ^ result) & sign) !== 0n);
    this.af = logical ? 0 : Number(((a ^ b ^ result) & 16n) !== 0n);
    this.zf = Number(result === 0n);
    this.sf = Number((result & sign) !== 0n);
    this.pf = this.parity(Number(result & 0xffn));
    return result;
  }

  private load(sz: number, addr: number): number {
    if (sz === 1) return this.read8(addr);
    if (sz === 2) return this.read16(addr);
    if (sz === 4) return this.read32(addr);
    return this.read64(addr);
  }
  private store(sz: number, addr: number, v: number): void {
    if (sz === 1) this.write8(addr, v);
    else if (sz === 2) this.write16(addr, v);
    else if (sz === 4) this.write32(addr, v);
    else this.write64(addr, v);
  }

  // ---- registers ----

  regRead(register: number): number {
    const idx = REG_BY_ID.get(register);
    if (idx === undefined) throw new Error(`reg_read(${register}) unsupported`);
    if (idx === -1) return this.rip;
    return this.lo[idx] + this.hi[idx] * 4294967296;
  }

  regWrite(register: number, value: number): void {
    const idx = REG_BY_ID.get(register);
    if (idx === undefined) throw new Error(`reg_write(${register}) unsupported`);
    if (idx === -1) {
      this.rip = value;
      return;
    }
    this.setQ(idx, value);
  }

  gprs(): number[] {
    const out = new Array(16);
    for (let i = 0; i < 16; i++) out[i] = this.getQ(i);
    return out;
  }

  private getQ(i: number): number {
    const hi = this.hi[i];
    if (hi >= 0x80000000) {
      // negative 64-bit value: represent exactly as a negative double
      // (avoids constructing values above 2^53)
      return this.lo[i] - (4294967296 - hi) * 4294967296;
    }
    return this.lo[i] + hi * 4294967296;
  }
  private setQ(i: number, v: number): void {
    if (v < 0) {
      const hi = Math.floor(v / 4294967296);
      this.lo[i] = v - hi * 4294967296;
      this.hi[i] = hi;
      return;
    }
    this.lo[i] = v % 4294967296;
    this.hi[i] = Math.floor(v / 4294967296);
  }
  private setL(i: number, v: number): void {
    this.lo[i] = v >>> 0;
    this.hi[i] = 0;
  }

  private regLoad(sz: number, i: number): number {
    if (sz === 8) return this.getQ(i);
    if (sz === 1) {
      const r = i & 7;
      if (this.curRex) return this.lo[i] & 0xff; // SPL/BPL/SIL/DIL with REX
      return r < 4 ? this.lo[i] & 0xff : (this.lo[i & 3] >>> 8) & 0xff;
    }
    if (sz === 2) return this.lo[i] & 0xffff;
    return this.lo[i];
  }
  private regStore(sz: number, i: number, v: number): void {
    if (sz === 8) {
      this.setQ(i, v);
      return;
    }
    if (sz === 1) {
      if (this.curRex) {
        this.lo[i] = (this.lo[i] & 0xffffff00) | (v & 0xff);
        return;
      }
      const r = i & 7;
      if (r < 4) this.lo[i] = (this.lo[i] & ~0xff & 0xffffffff) | (v & 0xff);
      else {
        const t = i & 3;
        this.lo[t] = (this.lo[t] & 0xffff00ff) | ((v & 0xff) << 8);
      }
      return;
    }
    if (sz === 2) {
      this.lo[i] = (this.lo[i] & 0xffff0000) | (v & 0xffff);
      return;
    }
    this.lo[i] = v >>> 0;
    this.hi[i] = 0;
  }

  // ---- hooks / control ----

  attachCodeHook(): void {}
  detachCodeHook(): void {}
  addCodeHook(begin: number, end: number): number {
    this.jit?.clear();
    this.hooks.push({ begin, end });
    return this.hooks.length;
  }
  hookDel(): void {}
  emuStop(): void {
    this.stopRequested = true;
  }
  close(): void {}

  /** Restores the faulting instruction address for a compiled block that threw. */
  jitFault(block: JitBlock, executed: number, error: unknown): void {
    if (executed === 0) return;
    this.rip = block.addresses[executed - 1];
    this.lastSize = block.instructions[executed - 1].size;
    if (error instanceof X86Fault && error.rip !== this.rip) {
      error.message = error.message.replace(/ at 0x[0-9a-f]+ /, ` at 0x${this.rip.toString(16)} `);
      error.rip = this.rip;
    }
  }

  hasCodeHook(address: number): boolean {
    for (const h of this.hooks) if (address >= h.begin && address <= h.end) return true;
    return false;
  }

  emuStart(begin: number, until: number, timeoutUs = 0, count = 0): void {
    this.rip = begin;
    this.stopRequested = false;
    const deadline = timeoutUs > 0 ? performance.now() + timeoutUs / 1000 : Infinity;
    const firstInstruction = this.insnCount;
    this.jit?.observe(this.onPostStep !== null);
    let nextTimeoutCheck = 0;
    let previousBlock: JitLink | null = null;
    while (this.rip !== until && !this.stopRequested) {
      const executed = this.insnCount - firstInstruction;
      if (count > 0 && executed >= count) break;
      if (executed >= nextTimeoutCheck) {
        if (performance.now() >= deadline) throw new X86Fault('execution timed out', this.rip, -1);
        nextTimeoutCheck = executed + 4096;
      }
      if (this.jit) {
        const prior = previousBlock;
        let block: JitBlock | null | undefined = prior?.next0;
        if (!block?.valid || block.start !== this.rip) block = prior?.next1;
        if (!block?.valid || block.start !== this.rip) {
          block = count > 0 ? this.jit.get(this.rip, until) : this.jit.find(this.rip, until);
          if (previousBlock && block) {
            previousBlock.next0 = previousBlock.next1;
            previousBlock.next1 = block;
            if (!previousBlock.targets.includes(block.start)) {
              if (previousBlock.targets.length >= 8) previousBlock.targets.shift();
              previousBlock.targets.push(block.start);
            }
          }
        }
        if (
          block &&
          !(until > block.start && until < block.end) &&
          (count === 0 || block.addresses.length <= count - executed)
        ) {
          previousBlock = this.runBatch(block, until, count);
          this.onJitBlock?.();
          continue;
        }
        previousBlock = null;
        this.jit.fallbackInstructions++;
        this.jit.fallbackAddresses.set(this.rip, (this.jit.fallbackAddresses.get(this.rip) ?? 0) + 1);
      }
      if (this.hasCodeHook(this.rip)) this.onCodeHook?.(this.rip, this.insnLength(this.rip));
      if (this.stopRequested) break;
      const prevAddr = this.rip;
      this.rip = this.step();
      this.onPostStep?.(prevAddr, this.lastSize);
      this.onJitBlock?.();
    }
  }

  /**
   * Runs linked compiled blocks, or the region built around the first one, as one batch.
   * A separate method keeps the loop optimized as an ordinary call instead of through OSR.
   */
  private runBatch(block: JitBlock, until: number, count: number): JitLink | null {
    const jit = this.jit!;
    const before = this.insnCount;
    const log = jit.executionLog;
    const logging = log !== null;
    let current: JitBlock = block;
    let link: JitLink | null;
    do {
      if (count === 0) {
        const region = current.region;
        if (region !== null && region.epoch === jit.epoch && region.until === until && region.logging === logging) {
          this.rip = region.run(this);
          if (region.generation < 2 && !region.index.has(this.rip)) {
            region.executed += this.insnCount - before;
            region.exitTargets.set(this.rip, (region.exitTargets.get(this.rip) ?? 0) + 1);
            if (++region.exits >= 2048) jit.growRegion(region, until);
          }
          link = region;
          break;
        }
        if (++current.hits === jit.regionHits) jit.buildRegion(current, until);
      }
      const blockStart = logging ? this.insnCount : 0;
      this.rip = current.run(this);
      log?.push({ block: current, count: this.insnCount - blockStart });
      link = current;
      if (current.observable || count > 0 || this.rip === until || this.insnCount - before >= 4096) break;
      let next: JitBlock | null = current.next0;
      if (!next?.valid || next.start !== this.rip) next = current.next1;
      if (!next?.valid || next.observable || next.start !== this.rip || (until > next.start && until < next.end)) break;
      current = next;
    } while (true);
    jit.compiledInstructions += this.insnCount - before;
    return link;
  }

  get instructionCount(): number {
    return this.insnCount;
  }

  // ---- decode helpers ----

  private fetch(a: number): number {
    return this.region(a).bytes[a - this.lastRegion!.base];
  }
  private imm(pos: number, n: number): number {
    let v = 0;
    for (let i = n - 1; i >= 0; i--) v = v * 256 + this.fetch(pos + i);
    return v;
  }
  private immS(pos: number, n: number): number {
    const v = this.imm(pos, n);
    const signBit = Math.pow(2, n * 8 - 1);
    return v >= signBit ? v - signBit * 2 : v;
  }

  /** Resolves the r/m operand (register or memory address). */
  private resolveRM(
    pos: number,
    rex: number,
    addrsize: number,
  ): { rm: number; mod: number; reg: number; next: number; addr: number; qaddr: bigint } {
    const m = this.fetch(pos);
    const mod = m >>> 6;
    const reg = ((m >>> 3) & 7) | (rex & 4 ? 8 : 0);
    const rm = (m & 7) | (rex & 1 ? 8 : 0);
    let next = pos + 1;
    let addr = 0;
    let qaddr = 0n;
    if (mod !== 3) {
      let base = -1,
        index = -1,
        scale = 1,
        disp = 0;
      let isRip = false;
      if ((rm & 7) === 4) {
        const sib = this.fetch(next++);
        scale = 1 << (sib >>> 6);
        const idx3 = (sib >>> 3) & 7;
        if (idx3 !== 4 || rex & 2) index = idx3 | (rex & 2 ? 8 : 0);
        const bse3 = sib & 7;
        base = bse3 | (rex & 1 ? 8 : 0);
        if (bse3 === 5 && mod === 0) {
          base = -1;
          disp = this.immS(next, 4);
          next += 4;
        }
      } else {
        base = rm;
        if (mod === 0 && (rm & 7) === 5) {
          base = -1;
          isRip = true; // x86-64: [RIP + disp32]
          disp = this.immS(next, 4);
          next += 4;
        }
      }
      if (mod === 1) {
        disp = this.immS(next, 1);
        next += 1;
      }
      if (mod === 2) {
        disp = this.immS(next, 4);
        next += 4;
      }
      let a = BigInt(disp);
      if (isRip) {
        a += BigInt(this.rip + this.insnLength(this.rip));
      } else {
        if (base >= 0) a += this.regQword(base);
        if (index >= 0) a += this.regQword(index) * BigInt(scale);
      }
      qaddr = BigInt.asUintN(addrsize * 8, a);
      addr = Number(qaddr);
    }
    return { rm, mod, reg, next, addr, qaddr };
  }

  private rmLoad(sz: number, r: { mod: number; rm: number; addr: number }): number {
    return r.mod === 3 ? this.regLoad(sz, r.rm) : this.load(sz, r.addr);
  }
  private rmStore(sz: number, r: { mod: number; rm: number; addr: number }, v: number): void {
    if (r.mod === 3) this.regStore(sz, r.rm, v);
    else this.store(sz, r.addr, v);
  }

  // ---- flags ----

  private parity(v: number): number {
    let x = v & 0xff;
    x ^= x >>> 4;
    x ^= x >>> 2;
    x ^= x >>> 1;
    return (x & 1) ^ 1;
  }

  private logicFlags(res: number, signBit: number): void {
    res = (res & (signBit * 2 - 1)) >>> 0;
    this.cf = 0;
    this.of = 0;
    this.af = 0;
    this.zf = res === 0 ? 1 : 0;
    this.sf = (res & signBit) !== 0 ? 1 : 0;
    this.pf = this.parity(res);
  }

  private addFlags(
    a: number,
    b: number,
    cin: number,
    res: number,
    mask: number,
    signBit: number,
    isSub: boolean,
  ): void {
    const ua = (a & mask) >>> 0;
    const ub = (b & mask) >>> 0;
    this.cf = Number(isSub ? ua < ub + cin : ua + ub + cin > mask);
    const rm = res & mask;
    this.zf = rm === 0 ? 1 : 0;
    this.sf = (rm & signBit) !== 0 ? 1 : 0;
    this.pf = this.parity(rm);
    if (isSub) this.of = ((a ^ b) & (a ^ rm) & signBit) !== 0 ? 1 : 0;
    else this.of = (~(a ^ b) & (a ^ rm) & signBit) !== 0 ? 1 : 0;
    this.af = ((a ^ b ^ rm) & 0x10) !== 0 ? 1 : 0;
  }

  private cond(cc: number): number {
    switch (cc) {
      case 0:
        return this.of;
      case 1:
        return 1 - this.of;
      case 2:
        return this.cf;
      case 3:
        return 1 - this.cf;
      case 4:
        return this.zf;
      case 5:
        return 1 - this.zf;
      case 6:
        return this.zf | this.cf;
      case 7:
        return 1 - (this.zf | this.cf);
      case 8:
        return this.sf;
      case 9:
        return 1 - this.sf;
      case 10:
        return this.pf;
      case 11:
        return 1 - this.pf;
      case 12:
        return this.sf ^ this.of;
      case 13:
        return 1 - (this.sf ^ this.of);
      case 14:
        return (this.sf ^ this.of) | this.zf;
      case 15:
        return 1 - ((this.sf ^ this.of) | this.zf);
      default:
        return 0;
    }
  }

  // ---- ALU ----

  private alu(kind: number, a: number, b: number, cin: number, sz: number): number {
    const mask = sz === 1 ? 0xff : sz === 2 ? 0xffff : sz === 4 ? 0xffffffff : -1;
    const signBit = sz === 1 ? 0x80 : sz === 2 ? 0x8000 : sz === 4 ? 0x80000000 : 0x8000000000000000;
    let res: number;
    switch (kind) {
      case 0:
        res = a + b;
        this.addFlags(a, b, 0, res, mask, signBit, false);
        break;
      case 1:
        res = sz === 8 ? logic64(a, b, 0) : a | b;
        this.logicFlags(res, signBit);
        break;
      case 2:
        res = a + b + cin;
        this.addFlags(a, b, cin, res, mask, signBit, false);
        break;
      case 3:
        res = a - b - cin;
        this.addFlags(a, b, cin, res, mask, signBit, true);
        break;
      case 4:
        res = sz === 8 ? logic64(a, b, 1) : a & b;
        this.logicFlags(res, signBit);
        break;
      case 5:
      case 7:
        res = a - b;
        this.addFlags(a, b, 0, res, mask, signBit, true);
        break;
      default:
        res = sz === 8 ? logic64(a, b, 2) : a ^ b;
        this.logicFlags(res, signBit);
        break;
    }
    return res;
  }

  private toSigned(v: number, sz: number): number {
    const signBit = sz === 1 ? 0x80 : sz === 2 ? 0x8000 : sz === 4 ? 0x80000000 : 0x8000000000000000;
    return v >= signBit ? v - signBit * 2 : v;
  }
  private signExtend(v: number, from: number, to: number): number {
    const s = this.toSigned(v, from);
    return s;
  }

  // ---- interpreter core ----

  /** Exact byte length of an instruction (subset length decoder). */
  insnLength(addr: number): number {
    let p = addr;
    let rex = 0;
    let opsize = 4;
    for (let i = 0; i < 15; i++) {
      const b = this.fetch(p);
      if (b === 0x66) {
        opsize = 2;
        p++;
        continue;
      }
      if (
        b === 0x67 ||
        b === 0xf0 ||
        b === 0xf2 ||
        b === 0xf3 ||
        b === 0x2e ||
        b === 0x36 ||
        b === 0x3e ||
        b === 0x26 ||
        b === 0x64 ||
        b === 0x65
      ) {
        p++;
        continue;
      }
      if (b >= 0x40 && b <= 0x4f) {
        rex = b;
        if (b & 8) opsize = 8;
        p++;
        continue;
      }
      break;
    }
    const op = this.fetch(p++);
    const prefixLen = p - addr - 1;
    const osz = opsize === 8 ? 8 : opsize;
    const modrmLen = (): number => {
      const m = this.fetch(p);
      const mod = m >>> 6;
      const rm = m & 7;
      if (mod === 3) return 1;
      let len = 1;
      if (rm === 4) {
        const sib = this.fetch(p + 1);
        len += 1;
        if ((sib & 7) === 5 && mod === 0) len += 4;
      } else if (rm === 5 && mod === 0) {
        len += 4;
      }
      if (mod === 1) len += 1;
      if (mod === 2) len += 4;
      return len;
    };
    const immLen = (n: number) => n;
    let len = prefixLen + 1;
    // opcodes with modrm
    // ALU forms 0-3 have modrm; forms 4/5 are the imm-accumulator forms
    const hasModrm =
      (op < 0x40 && (op & 7) < 4) ||
      [
        0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0xc0, 0xc1, 0xc6,
        0xc7, 0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff,
      ].includes(op);
    if (hasModrm) {
      const m = this.fetch(p);
      const mod = m >>> 6;
      const reg = (m >>> 3) & 7;
      len += modrmLen();
      const osz = opsize === 8 ? 8 : opsize;
      if ([0x69].includes(op)) len += 4;
      else if ([0x6b].includes(op)) len += 1;
      else if (op === 0x80 || op === 0x83 || op === 0xc0 || op === 0xc1 || op === 0xc6) len += 1;
      else if (op === 0x81 || op === 0xc7) len += osz === 8 ? 4 : osz;
      else if (op === 0xf6) len += reg === 0 || reg === 1 ? 1 : 0;
      else if (op === 0xf7) len += reg === 0 || reg === 1 ? (osz === 8 ? 4 : osz) : 0;
    } else {
      if (op >= 0x50 && op <= 0x5f) return prefixLen + 1;
      if (op >= 0xb0 && op <= 0xb7) return prefixLen + 2;
      if (op >= 0xb8 && op <= 0xbf) return prefixLen + 1 + (osz === 8 ? 8 : osz);
      if (op >= 0x70 && op <= 0x7f) return prefixLen + 2;
      if (op === 0xe0 || op === 0xe1 || op === 0xe2 || op === 0xe3 || op === 0xeb) return prefixLen + 2;
      if (op === 0xe8 || op === 0xe9) return prefixLen + 5;
      if (op === 0xea) return prefixLen + 7;
      if (op === 0x68) return prefixLen + 5;
      if (op === 0x6a) return prefixLen + 2;
      if (
        op === 0x04 ||
        op === 0x0c ||
        op === 0x14 ||
        op === 0x1c ||
        op === 0x24 ||
        op === 0x2c ||
        op === 0x34 ||
        op === 0x3c ||
        op === 0xa8 ||
        op === 0xcd ||
        op === 0xd4
      )
        return prefixLen + 2;
      if (
        op === 0x05 ||
        op === 0x0d ||
        op === 0x15 ||
        op === 0x1d ||
        op === 0x25 ||
        op === 0x2d ||
        op === 0x35 ||
        op === 0x3d ||
        op === 0xa9
      )
        return prefixLen + 1 + (osz === 8 ? 4 : osz);
      if (op === 0x0f) {
        const sub = this.fetch(p++);
        len = prefixLen + 2;
        const subHasModrm =
          (sub >= 0x40 && sub <= 0x4f) ||
          (sub >= 0x90 && sub <= 0x9f) ||
          [
            0x28, 0x29, 0x57, 0xa4, 0xa5, 0xac, 0xad, 0xaf, 0xba, 0xa3, 0xab, 0xb3, 0xbb, 0xb6, 0xb7, 0xbe, 0xbf, 0xbc,
            0xbd, 0xc0, 0xc1,
          ].includes(sub) ||
          sub === 0x69 ||
          (sub >= 0x10 && sub <= 0x1f);
        if (subHasModrm) len += modrmLen();
        if (sub >= 0x80 && sub <= 0x8f) len += 4;
        if (sub === 0xa4 || sub === 0xac || sub === 0xba) len += 1;
        return len;
      }
      if (op >= 0xd8 && op <= 0xdf) {
        len += modrmLen();
        return len;
      }
      if (
        op === 0xf4 ||
        op === 0x90 ||
        op === 0x98 ||
        op === 0x99 ||
        op === 0x9b ||
        op === 0x9c ||
        op === 0x9d ||
        op === 0x9e ||
        op === 0x9f ||
        op === 0xc3 ||
        op === 0xc9
      )
        return prefixLen + 1;
      if (op === 0xc2) return prefixLen + 3;
      if (op === 0xc8) return prefixLen + 4;
      if (op === 0xe5 || op === 0xe7 || op === 0xe4 || op === 0xe6 || op === 0xee || op === 0xef) return prefixLen + 2;
      if (op === 0xe8) return prefixLen + 5;
      if (op === 0xea) return prefixLen + 7;
    }
    return len;
  }

  /** Size in bytes of the most recently executed instruction. */
  lastSize = 1;

  step(): number {
    this.insnCount++;
    let p = this.rip;
    let rex = 0;
    let opsize = 4;
    let addrsize = 8;
    let rep = 0;
    for (;;) {
      const b = this.fetch(p++);
      if (b === 0x66) {
        opsize = 2;
        continue;
      }
      if (b === 0x67) {
        addrsize = 4;
        continue;
      }
      if (b === 0xf3) {
        rep = 1;
        continue;
      }
      if (b === 0xf2) {
        rep = 2;
        continue;
      }
      if (b === 0xf0 || b === 0x2e || b === 0x36 || b === 0x3e || b === 0x26 || b === 0x64 || b === 0x65) continue;
      if (b >= 0x40 && b <= 0x4f) {
        rex = b;
        if (b & 8) opsize = 8;
        continue;
      }
      this.curRex = rex;
      const startAddr = this.rip;
      this.lastSize = this.insnLength(startAddr);
      const next =
        b === 0x0f
          ? this.exec0f(this.fetch(p), rex, opsize, addrsize, rep, p + 1)
          : this.exec1(b, rex, opsize, addrsize, rep, p);
      return next;
    }
  }

  private exec1(op: number, rex: number, opsize: number, addrsize: number, rep: number, pos: number): number {
    const start = this.rip;
    const W = opsize; // 2 or 4 or 8
    const sz = W; // operand size for general ops
    const { rdx, rcx } = { rdx: RDX, rcx: RCX };

    // ---- ALU family ----
    if (op < 0x40 && (op & 7) < 6) {
      const kind = op >>> 3;
      const form = op & 7;
      const osz = form === 0 || form === 2 ? 1 : W;
      if (form <= 1) {
        // rm <- reg
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) {
          const result = this.aluQword(kind, this.rmQword(r), this.regQword(r.reg));
          if (kind !== 7) this.setRMQword(r, result);
          return r.next;
        }
        const a = this.rmLoad(osz, r);
        const b = this.regLoad(osz, r.reg);
        const res = this.alu(kind, a, b, kind === 2 || kind === 3 ? this.cf : 0, osz);
        if (kind !== 7) this.rmStore(osz, r, res);
        return start + (r.next - start);
      }
      if (form <= 3) {
        // reg <- rm
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) {
          const result = this.aluQword(kind, this.regQword(r.reg), this.rmQword(r));
          if (kind !== 7) this.setQword(r.reg, result);
          return r.next;
        }
        const a = this.regLoad(osz, r.reg);
        const b = this.rmLoad(osz, r);
        const res = this.alu(kind, a, b, kind === 2 || kind === 3 ? this.cf : 0, osz);
        if (kind !== 7) this.regStore(osz, r.reg, res);
        return start + (r.next - start);
      }
      if (form === 4) {
        // al, imm8
        const b = this.fetch(pos);
        const res = this.alu(kind, this.regLoad(1, RAX), b, kind === 2 || kind === 3 ? this.cf : 0, 1);
        if (kind !== 7) this.regStore(1, RAX, res);
        return pos + 1;
      }
      // form 5: eax, imm
      const immSz = osz === 8 ? 4 : osz;
      let b = this.imm(pos, immSz);
      if (osz === 8) b = this.signExtend(b, 4, 8);
      if (osz === 8) {
        const result = this.aluQword(kind, this.regQword(RAX), BigInt(b));
        if (kind !== 7) this.setQword(RAX, result);
        return pos + immSz;
      }
      const a = this.regLoad(osz, RAX);
      const res = this.alu(kind, a, b, kind === 2 || kind === 3 ? this.cf : 0, osz);
      if (kind !== 7) this.regStore(osz, RAX, res);
      return pos + immSz;
    }

    if (op >= 0x50 && op <= 0x57) {
      // push reg
      const reg = ((op - 0x50) & 7) | (rex & 1 ? 8 : 0);
      const value = this.regQword(reg);
      const sp = this.getQ(RSP) - 8;
      this.setQ(RSP, sp);
      this.writeQword(sp, value);
      return pos;
    }
    if (op >= 0x58 && op <= 0x5f) {
      // pop reg
      const reg = ((op - 0x58) & 7) | (rex & 1 ? 8 : 0);
      const sp = this.getQ(RSP);
      const v = this.readQword(sp);
      this.setQ(RSP, sp + 8);
      // push/pop default to 64-bit operands in long mode
      this.setQword(reg, v);
      return pos;
    }

    switch (op) {
      case 0x63: {
        // movsxd reg, rm32
        const r = this.resolveRM(pos, rex, addrsize);
        const v = this.rmLoad(4, r) | 0;
        this.setQ(r.reg, v);
        return start + (r.next - start);
      }
      case 0x68: {
        const v = this.immS(pos, 4);
        const sp = this.getQ(RSP) - 8;
        this.setQ(RSP, sp);
        this.write64(sp, v);
        return pos + 4;
      }
      case 0x6a: {
        const v = this.immS(pos, 1);
        const sp = this.getQ(RSP) - 8;
        this.setQ(RSP, sp);
        this.write64(sp, v);
        return pos + 1;
      }
      case 0x69: {
        // imul reg, rm, imm32 (32/64-bit)
        const r = this.resolveRM(pos, rex, addrsize);
        if (W === 8) {
          const a = BigInt.asIntN(64, this.rmQword(r));
          const imm = BigInt(this.immS(r.next, 4));
          this.setQword(r.reg, a * imm);
        } else {
          const a = this.rmLoad(4, r) | 0;
          const imm = this.immS(r.next, 4);
          this.setL(r.reg, Math.imul(a, imm) >>> 0);
        }
        return start + (r.next - start) + 4;
      }
      case 0x6b: {
        // imul reg, rm, imm8 (32/64-bit)
        const r = this.resolveRM(pos, rex, addrsize);
        if (W === 8) {
          const a = BigInt.asIntN(64, this.rmQword(r));
          const imm = BigInt(this.immS(r.next, 1));
          this.setQword(r.reg, a * imm);
        } else {
          const a = this.rmLoad(4, r) | 0;
          const imm = this.immS(r.next, 1);
          this.setL(r.reg, Math.imul(a, imm) >>> 0);
        }
        return start + (r.next - start) + 1;
      }
      case 0x80:
      case 0x81:
      case 0x82:
      case 0x83: {
        // grp1 rm, imm
        const osz = op === 0x80 || op === 0x82 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        const a = this.rmLoad(osz, r);
        let b: number;
        let immSz: number;
        if (op === 0x81) {
          immSz = osz === 8 ? 4 : osz;
          b = this.imm(r.next, immSz);
        } else {
          immSz = 1;
          b = this.immS(r.next, 1);
        }
        if (osz === 8) b = this.signExtend(b, op === 0x81 ? 4 : 1, 8);
        else if (op !== 0x81 && osz !== 1) b = this.signExtend(b, 1, osz);
        if (osz === 8) {
          const result = this.aluQword(r.reg & 7, this.rmQword(r), BigInt(b));
          if ((r.reg & 7) !== 7) this.setRMQword(r, result);
          return r.next + immSz;
        }
        const res = this.alu(r.reg, a, b, r.reg === 2 || r.reg === 3 ? this.cf : 0, osz);
        if (r.reg !== 7) this.rmStore(osz, r, res);
        return start + (r.next - start) + immSz;
      }
      case 0x84:
      case 0x85: {
        // test rm, reg
        const osz = op === 0x84 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) {
          this.aluQword(4, this.rmQword(r), this.regQword(r.reg));
          return r.next;
        }
        const v = this.rmLoad(osz, r) & this.regLoad(osz, r.reg);
        this.logicFlags(v, this.signBitOf(osz));
        return start + (r.next - start);
      }
      case 0x86:
      case 0x87: {
        // xchg
        const osz = op === 0x86 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) {
          const a = this.rmQword(r);
          this.setRMQword(r, this.regQword(r.reg));
          this.setQword(r.reg, a);
          return r.next;
        }
        const a = this.rmLoad(osz, r);
        const b = this.regLoad(osz, r.reg);
        this.rmStore(osz, r, b);
        this.regStore(osz, r.reg, a);
        return start + (r.next - start);
      }
      case 0x88:
      case 0x89: {
        // mov rm <- reg
        const osz = op === 0x88 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) this.setRMQword(r, this.regQword(r.reg));
        else this.rmStore(osz, r, this.regLoad(osz, r.reg));
        return start + (r.next - start);
      }
      case 0x8a:
      case 0x8b: {
        // mov reg <- rm
        const osz = op === 0x8a ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        if (osz === 8) this.setQword(r.reg, this.rmQword(r));
        else this.regStore(osz, r.reg, this.rmLoad(osz, r));
        return start + (r.next - start);
      }
      case 0x8d: {
        // lea
        const r = this.resolveRM(pos, rex, addrsize);
        if (r.mod === 3) throw new X86Fault('lea reg operand', start, op);
        if (W === 8) this.setQword(r.reg, r.qaddr);
        else this.regStore(W, r.reg, Number(BigInt.asUintN(W * 8, r.qaddr)));
        return start + (r.next - start);
      }
      case 0x90:
        return pos;
      case 0x98: {
        // cwde/cdqe
        if (W === 8) {
          const v = this.lo[RAX] | 0;
          this.setQ(RAX, v);
        } else {
          const v = (this.lo[RAX] << 16) >> 16;
          this.setL(RAX, v >>> 0);
        }
        return pos;
      }
      case 0x99: {
        // cdq/cqo
        if (W === 8) this.setQ(rdx, this.hi[RAX] & 0x80000000 ? -1 : 0);
        else this.setL(rdx, this.lo[RAX] & 0x80000000 ? 0xffffffff : 0);
        return pos;
      }
      case 0xa8:
      case 0xa9: {
        // test acc, imm
        const osz = op === 0xa8 ? 1 : W;
        const immSz = osz === 1 ? 1 : osz === 8 ? 4 : osz;
        const b = this.imm(pos, immSz);
        if (osz === 8) this.aluQword(4, this.regQword(RAX), BigInt(this.immS(pos, 4)));
        else this.logicFlags(this.regLoad(osz, RAX) & b, this.signBitOf(osz));
        return pos + immSz;
      }
      case 0xb0:
      case 0xb1:
      case 0xb2:
      case 0xb3:
      case 0xb4:
      case 0xb5:
      case 0xb6:
      case 0xb7: {
        const reg = ((op - 0xb0) & 7) | (rex & 1 ? 8 : 0);
        this.regStore(1, reg, this.fetch(pos));
        return pos + 1;
      }
      case 0xb8:
      case 0xb9:
      case 0xba:
      case 0xbb:
      case 0xbc:
      case 0xbd:
      case 0xbe:
      case 0xbf: {
        const reg = ((op - 0xb8) & 7) | (rex & 1 ? 8 : 0);
        if (W === 8) {
          this.setQword(reg, this.readQword(pos));
          return pos + 8;
        }
        this.regStore(W, reg, this.imm(pos, W));
        return pos + W;
      }
      case 0xc0:
      case 0xc1:
      case 0xd0:
      case 0xd1:
      case 0xd2:
      case 0xd3: {
        const osz = op === 0xc0 || op === 0xd0 || op === 0xd2 ? 1 : W;
        const countMask = osz === 8 ? 63 : 31;
        const r = this.resolveRM(pos, rex, addrsize);
        let count: number;
        let next = r.next;
        if (op === 0xc0 || op === 0xc1) {
          count = this.fetch(next) & countMask;
          next++;
        } else if (op === 0xd0 || op === 0xd1) count = 1;
        else count = this.lo[rcx] & countMask;
        const value = osz === 8 ? this.rmQword(r) : BigInt(this.rmLoad(osz, r));
        const result = this.shift(r.reg & 7, value, count, osz);
        if (osz === 8) this.setRMQword(r, result);
        else this.rmStore(osz, r, Number(result));
        return start + (next - start);
      }
      case 0xc2: {
        const imm = this.imm(pos, 2);
        const target = this.read64(this.getQ(RSP));
        this.setQ(RSP, this.getQ(RSP) + 8 + imm);
        return target;
      }
      case 0xc3: {
        const sp = this.getQ(RSP);
        const target = this.read64(sp);
        this.setQ(RSP, sp + 8);
        return target;
      }
      case 0xc6:
      case 0xc7: {
        // mov rm, imm
        const osz = op === 0xc6 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        const immSz = op === 0xc6 ? 1 : osz === 8 ? 4 : osz;
        const v = this.imm(r.next, immSz);
        this.rmStore(osz, r, osz === 8 ? this.signExtend(v, 4, 8) : v);
        return start + (r.next - start) + immSz;
      }
      case 0xc9: {
        // leave
        this.setQ(RSP, this.getQ(RBP));
        const v = this.read64(this.getQ(RSP));
        this.setQ(RBP, v);
        this.setQ(RSP, this.getQ(RSP) + 8);
        return pos;
      }
      case 0xcd:
        throw new X86Fault('int', start, op);
      case 0x9b:
        return pos; // fwait
      case 0x9c: {
        // pushfq
        const sp = this.getQ(RSP) - 8;
        this.setQ(RSP, sp);
        this.write64(sp, (this.flagsWord() & 0x0000000000fcffff) | 2);
        return pos;
      }
      case 0x9d: {
        // popfq
        const v = this.read64(this.getQ(RSP));
        this.setQ(RSP, this.getQ(RSP) + 8);
        this.setFlagsWord(Number(v & 0xffffffff));
        return pos;
      }
      case 0x9e: {
        // sahf
        this.setFlagsWordFromAH((this.lo[RAX] >>> 8) & 0xff);
        return pos;
      }
      case 0x9f: {
        // lahf
        const f = this.flagsWord() & 0xff;
        this.lo[RAX] = (this.lo[RAX] & 0xffff00ff) | (f << 8);
        return pos;
      }
      case 0xc8: {
        // enter imm16, imm8 (level 0 sufficient)
        const size = this.imm(pos, 2);
        const level = this.fetch(pos + 2);
        const sp = this.getQ(RSP) - 8;
        this.setQ(RSP, sp);
        this.write64(sp, this.getQ(RBP));
        if (level === 0) {
          this.setQ(RBP, sp);
          this.setQ(RSP, sp - size);
        } else {
          this.setQ(RBP, sp);
          this.setQ(RSP, sp - size);
        }
        return pos + 3;
      }
      case 0xd7: {
        // xlatb
        const table = addrsize === 4 ? this.lo[RBX] : this.getQ(RBX);
        const idx = this.lo[RAX] & 0xff;
        this.lo[RAX] = (this.lo[RAX] & 0xffffff00) | this.read8(table + idx);
        return pos;
      }
      case 0xe0:
      case 0xe1:
      case 0xe2: {
        // loopne/loope/loop
        const disp = this.immS(pos, 1);
        let cx = addrsize === 4 ? (this.lo[RCX] - 1) >>> 0 : this.wrap64(this.getQ(RCX) - 1);
        if (addrsize === 4) this.setL(RCX, cx);
        else {
          this.setQ(RCX, cx);
          cx = Number(cx);
        }
        const cxZero = addrsize === 4 ? this.lo[RCX] === 0 : this.getQ(RCX) === 0;
        let take = false;
        if (op === 0xe2) take = !cxZero;
        else if (op === 0xe1) take = !cxZero && this.zf === 1;
        else take = !cxZero && this.zf === 0;
        return take ? pos + 1 + disp : pos + 1;
      }
      case 0xe3: {
        // jrcxz
        const disp = this.immS(pos, 1);
        const cxZero = addrsize === 4 ? this.lo[RCX] === 0 : this.getQ(RCX) === 0;
        return cxZero ? pos + 1 + disp : pos + 1;
      }
      case 0xf4:
        throw new X86Fault('hlt', start, op);
      case 0xf5:
        this.cf ^= 1;
        return pos; // cmc
      case 0xf8:
        this.cf = 0;
        return pos; // clc
      case 0xf9:
        this.cf = 1;
        return pos; // stc
      case 0xfa:
      case 0xfb:
        return pos; // cli/sti
      case 0xfc:
        this.df = 0;
        return pos; // cld
      case 0xfd:
        this.df = 1;
        return pos; // std
      case 0xe8: {
        // call rel32
        const disp = this.immS(pos, 4);
        const sp = this.getQ(RSP) - 8;
        this.setQ(RSP, sp);
        this.write64(sp, pos + 4);
        return pos + 4 + disp;
      }
      case 0xe9:
        return pos + 4 + this.immS(pos, 4);
      case 0xeb:
        return pos + 1 + this.immS(pos, 1);
      case 0xf6: {
        // grp3 rm8
        const r = this.resolveRM(pos, rex, addrsize);
        const kind = r.reg;
        const a = this.rmLoad(1, r);
        if (kind === 0 || kind === 1) {
          this.logicFlags(a & this.fetch(r.next), 0x80);
          return start + (r.next - start) + 1;
        }
        if (kind === 2) {
          this.rmStore(1, r, ~a);
          return start + (r.next - start);
        }
        if (kind === 3) {
          const res = 0 - a;
          this.addFlags(0, a, 0, res, 0xff, 0x80, true);
          this.rmStore(1, r, res);
          return start + (r.next - start);
        }
        if (kind === 4) {
          const full = (this.lo[RAX] & 0xff) * a;
          this.regStore(2, RAX, full);
          this.cf = this.of = Number(full > 0xff);
          return start + (r.next - start);
        }
        if (kind === 5) {
          const prod = Math.imul(((this.lo[RAX] & 0xff) << 24) >> 24, (a << 24) >> 24);
          this.regStore(2, RAX, prod);
          this.cf = this.of = Number(prod < -128 || prod > 127);
          return start + (r.next - start);
        }
        if (kind === 6 || kind === 7) {
          const dividend = this.lo[RAX] & 0xffff;
          if (kind === 6) {
            if (a === 0) throw new X86Fault('div0', start, op);
            const q = Math.floor(dividend / a);
            if (q > 0xff) throw new X86Fault('div overflow', start, op);
            this.regStore(2, RAX, (q & 0xff) | (dividend % a << 8));
          } else {
            const y = (a << 24) >> 24;
            if (y === 0) throw new X86Fault('idiv0', start, op);
            const q = Math.trunc(this.toSigned(dividend, 2) / y);
            let rem = this.toSigned(dividend, 2) - q * y;
            if (q > 127 || q < -128) throw new X86Fault('idiv overflow', start, op);
            this.regStore(2, RAX, (q & 0xff) | ((rem & 0xff) << 8));
          }
          return start + (r.next - start);
        }
        throw new X86Fault('grp3 rm8', start, op);
      }
      case 0xf7: {
        // grp3 rm
        const osz = W;
        const r = this.resolveRM(pos, rex, addrsize);
        const kind = r.reg;
        const a = this.rmLoad(osz, r);
        if (kind === 0 || kind === 1) {
          const immSz = osz === 8 ? 4 : osz;
          if (osz === 8) this.aluQword(4, this.rmQword(r), BigInt(this.immS(r.next, 4)));
          else this.logicFlags(a & this.imm(r.next, immSz), this.signBitOf(osz));
          return start + (r.next - start) + immSz;
        }
        if (osz === 8 && (kind === 2 || kind === 3)) {
          this.setRMQword(r, kind === 2 ? ~this.rmQword(r) : this.aluQword(5, 0n, this.rmQword(r)));
          return r.next;
        }
        if (kind === 2) {
          this.rmStore(osz, r, ~a);
          return start + (r.next - start);
        }
        if (kind === 3) {
          const res = 0 - a;
          this.addFlags(0, a, 0, res, this.maskOf(osz), this.signBitOf(osz), true);
          this.rmStore(osz, r, res);
          return start + (r.next - start);
        }
        if (kind >= 4 && kind <= 7) {
          const bits = osz * 8;
          const width = BigInt(bits);
          const unsigned = (value: bigint) => BigInt.asUintN(bits, value);
          const signed = (value: bigint) => BigInt.asIntN(bits, value);
          const operand = osz === 8 ? this.rmQword(r) : BigInt(a);
          const low = unsigned(this.regQword(RAX));
          const high = unsigned(this.regQword(RDX));
          const write = (index: number, value: bigint) => {
            if (osz === 8) this.setQword(index, value);
            else this.regStore(osz, index, Number(unsigned(value)));
          };
          if (kind === 4 || kind === 5) {
            const product = kind === 4 ? low * operand : signed(low) * signed(operand);
            write(RAX, product);
            write(RDX, product >> width);
            this.cf = this.of = Number(kind === 4 ? product >> width !== 0n : signed(product) !== product);
          } else {
            const rawDividend = (high << width) | low;
            const dividend = kind === 6 ? rawDividend : BigInt.asIntN(bits * 2, rawDividend);
            const divisor = kind === 6 ? operand : signed(operand);
            if (divisor === 0n) throw new X86Fault('division by zero', start, op);
            const quotient = dividend / divisor;
            if ((kind === 6 ? unsigned(quotient) : signed(quotient)) !== quotient) {
              throw new X86Fault('division overflow', start, op);
            }
            write(RAX, quotient);
            write(RDX, dividend % divisor);
          }
          return r.next;
        }
        throw new X86Fault('grp3', start, op);
      }
      case 0xfe: {
        // inc/dec rm8
        const r = this.resolveRM(pos, rex, addrsize);
        const a = this.rmLoad(1, r);
        const res = r.reg === 0 ? a + 1 : a - 1;
        const savedCf = this.cf;
        this.addFlags(a, 1, 0, res, 0xff, 0x80, r.reg === 1);
        this.cf = savedCf; // inc/dec preserve CF
        this.rmStore(1, r, res);
        return start + (r.next - start);
      }
      case 0xff: {
        // grp5
        const r = this.resolveRM(pos, rex, addrsize);
        const kind = r.reg;
        const osz = W;
        // near call/jmp/push through a register or memory is 64-bit by
        // default in long mode (FF /2,/4,/6 ignore the missing REX.W)
        const a = this.rmLoad(kind === 2 || kind === 4 || kind === 6 ? 8 : osz === 8 ? 8 : 4, r);
        if (kind === 0 || kind === 1) {
          // inc/dec (CF preserved)
          if (osz === 8) {
            const savedCf = this.cf;
            this.setRMQword(r, this.aluQword(kind === 0 ? 0 : 5, this.rmQword(r), 1n));
            this.cf = savedCf;
            return r.next;
          }
          const res = kind === 0 ? a + 1 : a - 1;
          const savedCf = this.cf;
          this.addFlags(a, 1, 0, res, this.maskOf(osz), this.signBitOf(osz), kind === 1);
          this.cf = savedCf;
          this.rmStore(osz, r, res);
          return start + (r.next - start);
        }
        if (kind === 2) {
          // call rm
          const sp = this.getQ(RSP) - 8;
          this.setQ(RSP, sp);
          this.write64(sp, start + (r.next - start));
          return a;
        }
        if (kind === 4) return a; // jmp rm
        if (kind === 6) {
          // Read before updating RSP: PUSH RSP must save its original value.
          const value = this.rmQword(r);
          const sp = this.getQ(RSP) - 8;
          this.setQ(RSP, sp);
          this.writeQword(sp, value);
          return start + (r.next - start);
        }
        throw new X86Fault(`grp5 kind ${kind}`, start, op);
      }
      default:
        if (op >= 0xd8 && op <= 0xdf) return this.x87op(op, rex, addrsize, pos);
        if (op >= 0x70 && op <= 0x7f) {
          const disp = this.immS(pos, 1);
          return this.cond(op & 15) ? pos + 1 + disp : pos + 1;
        }
        if (op >= 0x91 && op <= 0x97) {
          // xchg eax, reg (0x90 is nop)
          const reg = ((op - 0x90) & 7) | (rex & 1 ? 8 : 0);
          const osz = W;
          if (osz === 8) {
            const a = this.regQword(RAX);
            this.setQword(RAX, this.regQword(reg));
            this.setQword(reg, a);
          } else {
            const a = this.regLoad(osz, RAX);
            this.regStore(osz, RAX, this.regLoad(osz, reg));
            this.regStore(osz, reg, a);
          }
          return pos;
        }
        if (
          op === 0xa4 ||
          op === 0xa5 ||
          op === 0xaa ||
          op === 0xab ||
          op === 0xac ||
          op === 0xad ||
          op === 0xae ||
          op === 0xaf ||
          op === 0xa6 ||
          op === 0xa7
        ) {
          return this.stringOp(op, rex, W, addrsize, rep, pos);
        }
        throw new X86Fault(`unimplemented opcode`, start, op);
    }
  }

  private flagsWord(): number {
    return (
      this.cf |
      2 |
      (this.pf << 2) |
      (this.af << 4) |
      (this.zf << 6) |
      (this.sf << 7) |
      (this.df << 10) |
      (this.of << 11)
    );
  }
  private setFlagsWord(v: number): void {
    this.cf = v & 1;
    this.pf = (v >> 2) & 1;
    this.af = (v >> 4) & 1;
    this.zf = (v >> 6) & 1;
    this.sf = (v >> 7) & 1;
    this.df = (v >> 10) & 1;
    this.of = (v >> 11) & 1;
  }
  private setFlagsWordFromAH(v: number): void {
    this.cf = v & 1;
    this.pf = (v >> 2) & 1;
    this.af = (v >> 4) & 1;
    this.zf = (v >> 6) & 1;
    this.sf = (v >> 7) & 1;
  }

  // shortcut: x87 state is approximate; implement full semantics before validating guest paths that depend on it.
  private readonly fpu = new Float64Array(8);
  private ftop = 0;

  private x87op(op: number, rex: number, addrsize: number, pos: number): number {
    const start = this.rip;
    const r = this.resolveRM(pos, rex, addrsize);
    const next = r.next;
    const regf = r.reg;
    const st = (i: number) => this.fpu[(this.ftop + i) & 7];
    const push = (v: number) => {
      this.ftop = (this.ftop + 7) & 7;
      this.fpu[this.ftop] = v;
    };
    const pop = () => {
      this.ftop = (this.ftop + 1) & 7;
    };
    const setZfPfCf = (a: number, b: number) => {
      if (a > b) {
        this.zf = 0;
        this.pf = 0;
        this.cf = 0;
      } else if (a < b) {
        this.zf = 0;
        this.pf = 0;
        this.cf = 1;
      } else {
        this.zf = 1;
        this.pf = 0;
        this.cf = 0;
      }
    };
    const mem = (szBytes: number): number => {
      if (szBytes === 4) {
        const v = this.read32(r.addr);
        const s = v >>> 31 ? -1 : 1;
        const e = (v >>> 23) & 0xff,
          f = v & 0x7fffff;
        return e === 0 ? s * f * 1.401298464324817e-45 : s * (1 + f / 8388608) * Math.pow(2, e - 127);
      }
      return this.read64(r.addr); // raw bits are a valid f64 pattern
    };
    const memInt = (szBytes: number): number =>
      szBytes === 2
        ? (this.read16(r.addr) << 16) >> 16
        : szBytes === 4
          ? this.read32(r.addr) | 0
          : this.read64(r.addr) | 0;

    if (r.mod !== 3) {
      switch (op) {
        case 0xd8: {
          // f32 arithmetic
          const m = mem(4);
          if (regf === 0) this.fpu[this.ftop] += m;
          else if (regf === 1) this.fpu[this.ftop] *= m;
          else if (regf === 4) this.fpu[this.ftop] -= m;
          else if (regf === 5) this.fpu[this.ftop] = m - this.fpu[this.ftop];
          else if (regf === 6) this.fpu[this.ftop] /= m;
          else if (regf === 7) this.fpu[this.ftop] = m / this.fpu[this.ftop];
          else setZfPfCf(this.fpu[this.ftop], m);
          if (regf === 3) pop();
          break;
        }
        case 0xd9: {
          if (regf === 0) push(mem(4));
          else if (regf === 2) this.store(4, r.addr, f32bits(this.fpu[this.ftop]));
          else if (regf === 3) {
            this.store(4, r.addr, f32bits(this.fpu[this.ftop]));
            pop();
          } else if (regf === 4 || regf === 6) {
            this.store(r.mod === 3 ? 28 : 28, r.addr, 0);
            this.store32x(r.addr, 28, 0);
          }
          break;
        }
        case 0xda: {
          // int32 arithmetic
          const m = memInt(4);
          if (regf === 0) this.fpu[this.ftop] += m;
          else if (regf === 1) this.fpu[this.ftop] *= m;
          else if (regf === 4) this.fpu[this.ftop] -= m;
          else if (regf === 5) this.fpu[this.ftop] = m - this.fpu[this.ftop];
          else if (regf === 6) this.fpu[this.ftop] /= m;
          else if (regf === 7) this.fpu[this.ftop] = m / this.fpu[this.ftop];
          else if (regf === 2 || regf === 3) setZfPfCf(this.fpu[this.ftop], m);
          if (regf === 3) pop();
          break;
        }
        case 0xdb: {
          if (regf === 0) push(memInt(4));
          else if (regf === 1) {
            this.write32(r.addr, truncateInt(this.fpu[this.ftop]));
            pop();
          } else if (regf === 2) this.write32(r.addr, truncateInt(this.fpu[this.ftop]));
          else if (regf === 3) {
            this.write32(r.addr, truncateInt(this.fpu[this.ftop]));
            pop();
          } else if (regf === 5) push(mem(8));
          else if (regf === 7) {
            this.write64(r.addr, f64bits(this.fpu[this.ftop]));
            pop();
          }
          break;
        }
        case 0xdc: {
          // f64 arithmetic
          const m = mem(8);
          if (regf === 0) this.fpu[this.ftop] += m;
          else if (regf === 1) this.fpu[this.ftop] *= m;
          else if (regf === 4) this.fpu[this.ftop] -= m;
          else if (regf === 5) this.fpu[this.ftop] = m - this.fpu[this.ftop];
          else if (regf === 6) this.fpu[this.ftop] /= m;
          else if (regf === 7) this.fpu[this.ftop] = m / this.fpu[this.ftop];
          else if (regf === 2 || regf === 3) setZfPfCf(this.fpu[this.ftop], m);
          if (regf === 3) pop();
          break;
        }
        case 0xdd: {
          if (regf === 0) push(mem(8));
          else if (regf === 2) this.write64(r.addr, f64bits(this.fpu[this.ftop]));
          else if (regf === 3) {
            this.write64(r.addr, f64bits(this.fpu[this.ftop]));
            pop();
          } else if (regf === 4) {
            /* frstor: junk */
          } else if (regf === 6) this.store32x(r.addr, 108, 0); // fnsave
          break;
        }
        case 0xde: {
          // int16 arithmetic
          const m = memInt(2);
          if (regf === 0) this.fpu[this.ftop] += m;
          else if (regf === 1) this.fpu[this.ftop] *= m;
          else if (regf === 4) this.fpu[this.ftop] -= m;
          else if (regf === 5) this.fpu[this.ftop] = m - this.fpu[this.ftop];
          else if (regf === 6) this.fpu[this.ftop] /= m;
          else if (regf === 7) this.fpu[this.ftop] = m / this.fpu[this.ftop];
          else if (regf === 2 || regf === 3) setZfPfCf(this.fpu[this.ftop], m);
          if (regf === 3) pop();
          break;
        }
        case 0xdf: {
          if (regf === 0) push(memInt(2));
          else if (regf === 1) {
            this.write64(r.addr, truncateInt(this.fpu[this.ftop]));
            pop();
          } else if (regf === 3) {
            this.write64(r.addr, truncateInt(this.fpu[this.ftop]));
            pop();
          } else if (regf === 5) push(mem(8));
          else if (regf === 7) {
            this.write64(r.addr, f64bits(this.fpu[this.ftop]));
            pop();
          }
          break;
        }
      }
      return start + (next - start);
    }
    // register forms (mod == 3)
    const rm = r.rm;
    switch (op) {
      case 0xd8: // fadd/fmul/... st(i)
      case 0xdc: {
        const v = st(rm);
        if (regf === 0) this.fpu[this.ftop] += v;
        else if (regf === 1) this.fpu[this.ftop] *= v;
        else if (regf === 4) this.fpu[this.ftop] -= v;
        else if (regf === 5) this.fpu[this.ftop] = v - this.fpu[this.ftop];
        else if (regf === 6) this.fpu[this.ftop] /= v;
        else if (regf === 7) this.fpu[this.ftop] = v / this.fpu[this.ftop];
        else if (regf === 2 || regf === 3) setZfPfCf(this.fpu[this.ftop], v);
        if (op === 0xdc && (regf === 3 || regf === 7)) pop();
        if (op === 0xd8 && regf === 3) pop();
        break;
      }
      case 0xd9: {
        if (regf === 0)
          push(st(rm)); // fld st(i)
        else if (regf === 2) {
          /* fnop */
        } else if (regf === 4 && rm === 0)
          this.fpu[this.ftop] = -this.fpu[this.ftop]; // fchs
        else if (regf === 5 && rm === 0)
          push(1); // fld1
        else if (regf === 5 && rm === 1)
          push(Math.LN2); // fldl2t approx
        else if (regf === 5 && rm === 2)
          push(Math.LOG2E); // fldl2e approx
        else if (regf === 5 && rm === 3)
          push(Math.PI); // fldpi
        else if (regf === 5 && rm === 4)
          push(0); // fldz
        else if (regf === 6 && rm === 6)
          this.ftop = (this.ftop + 7) & 7; // fdecstp
        else if (regf === 6 && rm === 7)
          this.ftop = (this.ftop + 1) & 7; // fincstp
        else if (regf === 7 && rm === 0) {
          /* f2xm1 approx */ this.fpu[this.ftop] = Math.pow(2, this.fpu[this.ftop]) - 1;
        } else if (regf === 7 && rm === 2)
          this.fpu[this.ftop] = Math.sqrt(this.fpu[this.ftop]); // fsqrt
        else if (regf === 7 && rm === 4)
          this.fpu[this.ftop] = Math.round(this.fpu[this.ftop]); // frndint
        else if (regf === 7 && rm === 6)
          this.fpu[this.ftop] = Math.sin(this.fpu[this.ftop]); // fsin
        else if (regf === 7 && rm === 7) this.fpu[this.ftop] = Math.cos(this.fpu[this.ftop]); // fcos
        break;
      }
      case 0xdb: {
        if (regf === 5 || regf === 6) {
          setZfPfCf(this.fpu[this.ftop], st(rm));
          if (regf === 6) pop();
        } // fucomi/fucomip
        else if (regf === 7) {
          setZfPfCf(this.fpu[this.ftop], st(rm));
          pop();
        } // fcomip
        break;
      }
      case 0xdd: {
        if (regf === 0) push(st(rm));
        else if (regf === 2) this.fpu[rm] = this.fpu[this.ftop];
        else if (regf === 3) {
          this.fpu[rm] = this.fpu[this.ftop];
          pop();
        } else if (regf === 4 || regf === 5)
          setZfPfCf(this.fpu[this.ftop], st(rm)); // fucom
        else if (regf === 6 || regf === 7) {
          setZfPfCf(this.fpu[this.ftop], st(rm));
          pop();
        } // fucomp
        break;
      }
      case 0xdf: {
        if (rm === 0 && regf === 4) {
          // fnstsw ax
          this.lo[RAX] = ((this.ftop << 11) | (this.zf ? 0x40 : 0) | (this.cf ? 1 : 0)) >>> 0;
        }
        break;
      }
    }
    return start + (next - start);
  }

  private store32x(addr: number, count: number, value: number): void {
    const zeros = new Uint8Array(count).fill(value);
    this.memWrite(addr, zeros);
  }

  // Modulo-2^64 is applied by setQ's floor split; a +2^64 roundtrip here
  // would destroy precision (double spacing at 2^64 is 2048).
  private wrap64(v: number): number {
    return v;
  }
  private wrap32(v: number): number {
    return ((v % 4294967296) + 4294967296) % 4294967296;
  }
  private maskOf(sz: number): number {
    return sz === 1 ? 0xff : sz === 2 ? 0xffff : sz === 4 ? 0xffffffff : -1;
  }
  private signBitOf(sz: number): number {
    return sz === 1 ? 0x80 : sz === 2 ? 0x8000 : sz === 4 ? 0x80000000 : 0x8000000000000000;
  }

  private stringOp(op: number, rex: number, W: number, addrsize: number, rep: number, pos: number): number {
    const byte = (op & 1) === 0;
    const sz = byte ? 1 : W === 8 ? 8 : W === 2 ? 2 : 4;
    const kind = op & 0xfe;
    const count = rep ? this.lo[RCX] : 1;
    const step = (this.df ? -1 : 1) * sz;
    let si = addrsize === 4 ? this.lo[RSI] : this.getQ(RSI);
    let di = addrsize === 4 ? this.lo[RDI] : this.getQ(RDI);
    let executed = 0;
    for (let i = 0; i < count; i++) {
      if (kind === 0xa4) {
        // movs
        if (sz === 8) this.writeQword(di, this.readQword(si));
        else this.store(sz, di, this.load(sz, si));
        si += step;
        di += step;
      } else if (kind === 0xa6) {
        // cmps
        if (sz === 8) this.aluQword(7, this.readQword(si), this.readQword(di));
        else this.alu(7, this.load(sz, si), this.load(sz, di), 0, sz);
        si += step;
        di += step;
        executed = i + 1;
        if (rep === 1 && this.zf === 0) break;
        if (rep === 2 && this.zf === 1) break;
      } else if (kind === 0xaa) {
        // stos
        if (sz === 8) this.writeQword(di, this.regQword(RAX));
        else this.store(sz, di, this.regLoad(sz, RAX));
        di += step;
      } else if (kind === 0xac) {
        // lods
        if (sz === 8) this.setQword(RAX, this.readQword(si));
        else this.regStore(sz, RAX, this.load(sz, si));
        si += step;
      } else if (kind === 0xae) {
        // scas
        if (sz === 8) this.aluQword(7, this.regQword(RAX), this.readQword(di));
        else this.alu(7, this.regLoad(sz, RAX), this.load(sz, di), 0, sz);
        di += step;
        executed = i + 1;
        if (rep === 1 && this.zf === 0) break;
        if (rep === 2 && this.zf === 1) break;
      }
      executed = i + 1;
    }
    if (addrsize === 4) {
      this.setL(RSI, si);
      this.setL(RDI, di);
    } else {
      this.setQ(RSI, si);
      this.setQ(RDI, di);
    }
    if (rep) this.setL(RCX, Math.max(0, count - executed));
    return pos;
  }

  private shift(kind: number, value: bigint, count: number, sz: number): bigint {
    const bits = sz * 8;
    const width = BigInt(bits);
    const mask = (1n << width) - 1n;
    value &= mask;
    count &= bits === 64 ? 63 : 31;
    if (kind <= 1) count %= bits;
    else if (kind <= 3) count %= bits + 1;
    if (count === 0) return value;
    const n = BigInt(count);
    let result: bigint;
    if (kind <= 1) {
      result =
        kind === 0 ? ((value << n) | (value >> (width - n))) & mask : ((value >> n) | (value << (width - n))) & mask;
      this.cf = Number((kind === 0 ? result : result >> (width - 1n)) & 1n);
    } else if (kind <= 3) {
      const extended = (BigInt(this.cf) << width) | value;
      const extendedWidth = width + 1n;
      const rotated =
        kind === 2
          ? (extended << n) | (extended >> (extendedWidth - n))
          : (extended >> n) | (extended << (extendedWidth - n));
      result = rotated & mask;
      this.cf = Number((rotated >> width) & 1n);
    } else {
      if (kind === 4 || kind === 6) {
        result = (value << n) & mask;
        this.cf = Number((value >> (width - n)) & 1n);
      } else {
        result = (kind === 7 ? BigInt.asIntN(bits, value) >> n : value >> n) & mask;
        this.cf = Number((value >> (n - 1n)) & 1n);
      }
      this.zf = Number(result === 0n);
      this.sf = Number((result >> (width - 1n)) & 1n);
      this.pf = this.parity(Number(result & 0xffn));
    }
    if (count === 1) {
      const msb = Number((result >> (width - 1n)) & 1n);
      if (kind === 1 || kind === 3) this.of = msb ^ Number((result >> (width - 2n)) & 1n);
      else if (kind === 5) this.of = Number((value >> (width - 1n)) & 1n);
      else if (kind === 7) this.of = 0;
      else this.of = msb ^ this.cf;
    }
    return result;
  }

  private exec0f(sub: number, rex: number, W: number, addrsize: number, rep: number, pos: number): number {
    const start = this.rip;
    switch (sub) {
      case 0x28:
      case 0x29:
      case 0x57: {
        const r = this.resolveRM(pos, rex, addrsize);
        if (sub !== 0x57 && r.mod !== 3 && r.addr % 16 !== 0) {
          throw new X86Fault('unaligned movaps', start, 0x0f00 | sub);
        }
        if (sub === 0x29) {
          if (r.mod === 3) this.xmm[r.rm].set(this.xmm[r.reg]);
          else this.memWrite(r.addr, this.xmm[r.reg]);
        } else {
          const source = r.mod === 3 ? this.xmm[r.rm] : this.memRead(r.addr, 16);
          if (sub === 0x28) this.xmm[r.reg].set(source);
          else for (let i = 0; i < 16; i++) this.xmm[r.reg][i] ^= source[i];
        }
        return r.next;
      }
      case 0x05:
        return pos; // syscall — not expected
      case 0x1e:
      case 0x1f:
      case 0x18:
      case 0x19:
      case 0x1a:
      case 0x1b:
      case 0x1c:
      case 0x1d: {
        // hint nops with modrm
        const r = this.resolveRM(pos, rex, addrsize);
        return start + (r.next - start);
      }
      case 0x31: {
        // rdtsc
        let t: number;
        if (this.rdtscQueue) {
          if (this.rdtscQueue.length === 0) throw new X86Fault('RDTSC replay exhausted', start, 0x0f31);
          t = this.rdtscQueue.shift()!;
        } else {
          t = this.rdtscProvider ? this.rdtscProvider() : ++this.tsc;
        }
        this.setL(RAX, t % 4294967296);
        this.setL(RDX, Math.floor(t / 4294967296) % 4294967296);
        return pos;
      }
      case 0x40:
      case 0x41:
      case 0x42:
      case 0x43:
      case 0x44:
      case 0x45:
      case 0x46:
      case 0x47:
      case 0x48:
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4c:
      case 0x4d:
      case 0x4e:
      case 0x4f: {
        const r = this.resolveRM(pos, rex, addrsize);
        if (this.cond(sub & 15)) {
          const osz = W;
          if (osz === 8) this.setQword(r.reg, this.rmQword(r));
          else this.regStore(osz, r.reg, this.rmLoad(osz, r));
        }
        return start + (r.next - start);
      }
      case 0x80:
      case 0x81:
      case 0x82:
      case 0x83:
      case 0x84:
      case 0x85:
      case 0x86:
      case 0x87:
      case 0x88:
      case 0x89:
      case 0x8a:
      case 0x8b:
      case 0x8c:
      case 0x8d:
      case 0x8e:
      case 0x8f: {
        const disp = this.immS(pos, 4);
        return this.cond(sub & 15) ? pos + 4 + disp : pos + 4;
      }
      case 0x90:
      case 0x91:
      case 0x92:
      case 0x93:
      case 0x94:
      case 0x95:
      case 0x96:
      case 0x97:
      case 0x98:
      case 0x99:
      case 0x9a:
      case 0x9b:
      case 0x9c:
      case 0x9d:
      case 0x9e:
      case 0x9f: {
        const r = this.resolveRM(pos, rex, addrsize);
        this.rmStore(1, r, this.cond(sub & 15));
        return start + (r.next - start);
      }
      case 0xa2: {
        // Match the vendored Unicorn Haswell profile used by the guest's CPU checks.
        const leaf = this.lo[RAX];
        if (leaf === 0) {
          this.setL(RAX, 0x0d);
          this.setL(RBX, 0x756e6547);
          this.setL(RCX, 0x6c65746e);
          this.setL(RDX, 0x49656e69);
        } else if (leaf === 1) {
          this.setL(RAX, 0x306c4);
          this.setL(RBX, 0x800);
          this.setL(RCX, 0xced82203);
          this.setL(RDX, 0x078bfbfd);
        } else {
          throw new X86Fault(`unsupported cpuid leaf 0x${leaf.toString(16)}`, start, 0x0fa2);
        }
        return pos;
      }
      case 0xa4:
      case 0xa5:
      case 0xac:
      case 0xad: {
        const r = this.resolveRM(pos, rex, addrsize);
        const immediate = (sub & 1) === 0;
        const count = (immediate ? this.fetch(r.next) : this.lo[RCX]) & (W === 8 ? 63 : 31);
        if (count !== 0) {
          const width = BigInt(W * 8);
          const n = BigInt(count);
          const dest = W === 8 ? this.rmQword(r) : BigInt(this.rmLoad(W, r));
          const source = W === 8 ? this.regQword(r.reg) : BigInt(this.regLoad(W, r.reg));
          const right = (sub & 8) !== 0;
          const result = BigInt.asUintN(
            W * 8,
            right ? (dest >> n) | (source << (width - n)) : (dest << n) | (source >> (width - n)),
          );
          this.cf = Number((right ? dest >> (n - 1n) : dest >> (width - n)) & 1n);
          this.zf = Number(result === 0n);
          this.sf = Number((result >> (width - 1n)) & 1n);
          this.pf = this.parity(Number(result & 0xffn));
          if (count === 1) this.of = Number(((result ^ dest) >> (width - 1n)) & 1n);
          if (W === 8) this.setRMQword(r, result);
          else this.rmStore(W, r, Number(result));
        }
        return r.next + Number(immediate);
      }
      case 0xaf: {
        // imul reg, rm
        const osz = W;
        const r = this.resolveRM(pos, rex, addrsize);
        const b = this.rmLoad(osz, r);
        if (osz === 8) {
          const prod = BigInt.asIntN(64, this.regQword(r.reg)) * BigInt.asIntN(64, this.rmQword(r));
          this.setQword(r.reg, prod);
        } else {
          this.setL(r.reg, Math.imul(this.lo[r.reg] | 0, b | 0) >>> 0);
        }
        return start + (r.next - start);
      }
      case 0xa3:
      case 0xab:
      case 0xb3:
      case 0xbb:
      case 0xba: {
        const r = this.resolveRM(pos, rex, addrsize);
        const immediate = sub === 0xba;
        const kind = immediate ? r.reg & 7 : 4 + ((sub >> 3) & 3);
        if (kind < 4) throw new X86Fault('invalid bit-test group', start, 0x0fba);
        const offset = immediate ? BigInt(this.fetch(r.next)) : BigInt.asIntN(W * 8, this.regQword(r.reg));
        if (!immediate && r.mod !== 3) r.addr += Number((offset >> BigInt(W === 8 ? 6 : W === 4 ? 5 : 4)) * BigInt(W));
        const bit = 1n << (offset & BigInt(W * 8 - 1));
        const value = W === 8 ? this.rmQword(r) : BigInt(this.rmLoad(W, r));
        this.cf = Number((value & bit) !== 0n);
        if (kind !== 4) {
          const result = kind === 5 ? value | bit : kind === 6 ? value & ~bit : value ^ bit;
          if (W === 8) this.setRMQword(r, result);
          else this.rmStore(W, r, Number(result));
        }
        return r.next + Number(immediate);
      }
      case 0xb6:
      case 0xb7: {
        // movzx
        const srcSz = sub === 0xb6 ? 1 : 2;
        const r = this.resolveRM(pos, rex, addrsize);
        const v = r.mod === 3 ? this.regLoad(srcSz, r.rm) : this.load(srcSz, r.addr);
        this.regStore(W, r.reg, v);
        return start + (r.next - start);
      }
      case 0xbe:
      case 0xbf: {
        // movsx
        const srcSz = sub === 0xbe ? 1 : 2;
        const r = this.resolveRM(pos, rex, addrsize);
        const raw = r.mod === 3 ? this.regLoad(srcSz, r.rm) : this.load(srcSz, r.addr);
        const v = this.signExtend(raw, srcSz, W === 8 ? 8 : W);
        this.regStore(W, r.reg, v);
        return start + (r.next - start);
      }
      case 0xbc:
      case 0xbd: {
        // bsf/bsr (scan bits)
        const osz = W;
        const r = this.resolveRM(pos, rex, addrsize);
        const v = osz === 8 ? this.rmQword(r) : BigInt(this.rmLoad(osz, r));
        if (v === 0n) {
          this.zf = 1;
          return start + (r.next - start);
        }
        this.zf = 0;
        let idx: number;
        if (sub === 0xbc) {
          idx = 0;
          while (((v >> BigInt(idx)) & 1n) === 0n) idx++;
        } else {
          idx = osz * 8 - 1;
          while (((v >> BigInt(idx)) & 1n) === 0n) idx--;
        }
        this.regStore(osz, r.reg, idx);
        return start + (r.next - start);
      }
      case 0xc0:
      case 0xc1: {
        // xadd rm, reg
        const osz = sub === 0xc0 ? 1 : W;
        const r = this.resolveRM(pos, rex, addrsize);
        const a = this.rmLoad(osz, r);
        const b = this.regLoad(osz, r.reg);
        if (osz === 8) {
          const original = this.rmQword(r);
          const result = this.aluQword(0, original, this.regQword(r.reg));
          this.setQword(r.reg, original);
          this.setRMQword(r, result);
          return r.next;
        }
        const res = this.alu(0, a, b, 0, osz);
        this.regStore(osz, r.reg, a);
        this.rmStore(osz, r, res);
        return start + (r.next - start);
      }
      case 0xc8:
      case 0xc9:
      case 0xca:
      case 0xcb:
      case 0xcc:
      case 0xcd:
      case 0xce:
      case 0xcf: {
        // bswap
        const reg = (sub & 7) | (rex & 1 ? 8 : 0);
        if (W === 8) {
          let value = this.regQword(reg);
          let swapped = 0n;
          for (let i = 0; i < 8; i++) {
            swapped = (swapped << 8n) | (value & 0xffn);
            value >>= 8n;
          }
          this.setQword(reg, swapped);
        } else {
          const v = this.lo[reg];
          this.setL(reg, (((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >>> 8) & 0xff00) | (v >>> 24)) >>> 0);
        }
        return pos;
      }
      default:
        throw new X86Fault(`unimplemented 0f ${sub.toString(16)}`, start, 0x0f00 | sub);
    }
  }
}
