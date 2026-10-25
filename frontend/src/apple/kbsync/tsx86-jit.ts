// Basic-block and region translation for the validated TS interpreter. Unsupported
// instructions remain interpreter steps; generated code only contains decoded numeric operands.
import type { TsX86Engine } from './tsx86';

/** Cached mapping for one generated memory access, or for one base-register span. */
export interface MemorySite {
  base: number;
  end: number;
  bytes: Uint8Array | null;
  view: DataView | null;
}

/** Successor cache shared by blocks and regions so the dispatcher can link either. */
export interface JitLink {
  next0: JitBlock | null;
  next1: JitBlock | null;
  /** Most recent distinct successors; seeds region formation after indirect jumps. */
  targets: number[];
}

export interface JitBlock extends JitLink {
  start: number;
  end: number;
  addresses: number[];
  instructions: Instruction[];
  observable: boolean;
  valid: boolean;
  sites: MemorySite[];
  run: (engine: TsX86Engine) => number;
  hits: number;
  region: JitRegion | null;
}

/** Hot blocks compiled into one function that keeps guest registers in locals between them. */
export interface JitRegion extends JitLink {
  start: number;
  members: JitBlock[];
  index: Map<number, number>;
  epoch: number;
  until: number;
  logging: boolean;
  generation: number;
  exits: number;
  executed: number;
  exitTargets: Map<number, number>;
  sites: MemorySite[];
  run: (engine: TsX86Engine) => number;
}

type Operand = { reg: number } | { address: string; lower: string; upper: string; shared?: SharedBase };
interface SharedBase {
  base: number;
  disp: number;
}
interface SharedAccess extends SharedBase {
  size: number;
}
interface Instruction {
  address: number;
  size: number;
  body: string;
  target?: string;
  writes: boolean;
  memoryRead: boolean;
  flagsRead: number;
  flagsWritten: number;
  /** Index-free operands addressed through a base register; they share one span check. */
  shared: SharedAccess[];
}

/** Block executions before the dispatcher compiles a region around a block. */
export const REGION_HITS = 500000;
/** Region exits to non-member addresses before the region is grown once around them. */
const REGION_GROW_EXITS = 2048;
const REGION_MAX_BLOCKS = 64;
/** Generated body text per region; larger functions fall off V8's top optimizing tier. */
const REGION_MAX_BODY = 18000;
/** Times a region may be rebuilt around its frequent exits. */
const REGION_MAX_GENERATION = 2;
/** Instructions a region runs before returning so the dispatcher can check the deadline. */
const REGION_BUDGET = 8192;
const REGION_LIMIT = 1024;

const U32 = 4294967296;
const ALL_FLAGS = 63;
const CONDITION_FLAGS = [32, 32, 1, 1, 8, 8, 9, 9, 16, 16, 2, 2, 48, 48, 56, 56];
function multiplyHigh(a: number, b: number): number {
  const middle = (a >>> 16) * (b & 65535) + (a & 65535) * (b >>> 16);
  const lower = (a & 65535) * (b & 65535) + (middle & 65535) * 65536;
  return ((a >>> 16) * (b >>> 16) + Math.floor(middle / 65536) + Math.floor(lower / U32)) >>> 0;
}
const low = (reg: number) => `l[${reg}]`;
const high = (reg: number) => `h[${reg}]`;
const signed = (value: number) => (value < 0 ? String(value) : `+${value}`);
const conditions = [
  'e.of',
  '!e.of',
  'e.cf',
  '!e.cf',
  'e.zf',
  '!e.zf',
  '(e.cf|e.zf)',
  '!(e.cf|e.zf)',
  'e.sf',
  '!e.sf',
  'e.pf',
  '!e.pf',
  '(e.sf^e.of)',
  '!(e.sf^e.of)',
  '(e.zf|(e.sf^e.of))',
  '!(e.zf|(e.sf^e.of))',
];
const HEADER = '"use strict";const l=e.lo,h=e.hi,epoch=e.jit.epoch;let a,b,ah,bh,r,rh,t,c,m,n;';

export class X86JitCompiler {
  readonly multiplyHigh = multiplyHigh;
  epoch = 0;
  compiledInstructions = 0;
  fallbackInstructions = 0;
  compilationMs = 0;
  compilations = 0;
  invalidations = 0;
  regionsBuilt = 0;
  regionInstructions = 0;
  regionHits = REGION_HITS;
  // Code writes can exit a block before its decoded instruction list ends.
  executionLog: { block: JitBlock; count: number }[] | null = null;
  readonly fallbackAddresses = new Map<number, number>();
  private blocks = new Map<number, JitBlock | null>();
  private visits = new Map<number, number>();
  private codePages = new Map<number, Set<number>>();
  private codeLow = Infinity;
  private codeHigh = 0;
  private observed = false;

  constructor(private readonly engine: TsX86Engine) {}

  clear(): void {
    for (const block of this.blocks.values()) {
      if (block) block.valid = false;
    }
    this.blocks.clear();
    this.visits.clear();
    this.codePages.clear();
    this.codeLow = Infinity;
    this.codeHigh = 0;
    this.epoch++;
  }

  invalidate(address: number, size: number): void {
    if (address + size <= this.codeLow || address >= this.codeHigh) return;
    let affected: Set<number> | null = null;
    for (let page = Math.floor(address / 4096), end = Math.floor((address + size - 1) / 4096); page <= end; page++) {
      const owners = this.codePages.get(page);
      if (owners) {
        affected ??= new Set();
        for (const start of owners) affected.add(start);
      }
    }
    if (!affected?.size) return;
    this.invalidations++;
    this.epoch++;
    for (const start of affected) {
      const block = this.blocks.get(start);
      if (block) block.valid = false;
      this.blocks.delete(start);
    }
    for (const [page, owners] of this.codePages) {
      for (const start of affected) owners.delete(start);
      if (owners.size === 0) this.codePages.delete(page);
    }
  }

  observe(enabled: boolean): void {
    if (this.observed === enabled) return;
    this.observed = enabled;
    this.clear();
  }

  find(address: number, until: number): JitBlock | null {
    if (!this.observed && !this.blocks.has(address)) {
      const visits = (this.visits.get(address) ?? 0) + 1;
      this.visits.set(address, visits);
      // Cold paths cost less to interpret than to compile and run just once.
      if (visits < 4) return null;
    }
    return this.get(address, until);
  }

  get(address: number, until = 0): JitBlock | null {
    const cached = this.blocks.get(address);
    if (cached !== undefined) return cached;
    const started = performance.now();
    const instructions: Instruction[] = [];
    let next = address;
    for (let i = 0; i < 128; i++) {
      if (next === until) break;
      let instruction: Instruction | null;
      try {
        instruction = this.decode(next);
      } catch (error) {
        if (instructions.length === 0) throw error;
        break;
      }
      if (!instruction) break;
      instructions.push(instruction);
      next += instruction.size;
      if (instruction.target !== undefined) break;
    }
    const block = instructions.length ? this.compile(instructions) : null;
    this.blocks.set(address, block);
    this.compilationMs += performance.now() - started;
    this.compilations++;
    // Include unsupported first instructions: replacing one must invalidate the fallback cache.
    for (let page = Math.floor(address / 4096); page <= Math.floor((Math.max(next, address + 15) - 1) / 4096); page++) {
      let owners = this.codePages.get(page);
      if (!owners) this.codePages.set(page, (owners = new Set()));
      owners.add(address);
      this.codeLow = Math.min(this.codeLow, page * 4096);
      this.codeHigh = Math.max(this.codeHigh, (page + 1) * 4096);
    }
    return block;
  }

  private compile(instructions: Instruction[]): JitBlock {
    const observable =
      this.observed || instructions.some((instruction) => this.engine.hasCodeHook(instruction.address));
    // A block may only discard flags overwritten before any observer, fault or exit.
    if (!observable) {
      let live = ALL_FLAGS;
      for (let i = instructions.length - 1; i >= 0; i--) {
        const instruction = instructions[i];
        if (instruction.writes) live = ALL_FLAGS;
        if ((live & instruction.flagsWritten) === 0) {
          instruction.body = instruction.body.replace(/\/\*flags\*\/[\s\S]*?\/\*endflags\*\//g, '');
        }
        live = (live & ~instruction.flagsWritten) | instruction.flagsRead;
        if (instruction.memoryRead) live = ALL_FLAGS;
      }
    }
    const shared: MemorySite[] = [];
    const spans: Span[] = [];
    const versions = new Map<number, number>();
    const parts = [HEADER];
    for (let i = 0; i < instructions.length; i++) {
      const instruction = instructions[i];
      const { address, size, target, writes } = instruction;
      const next = address + size;
      if (observable || writes || instruction.memoryRead || i === instructions.length - 1) {
        if (observable) parts.push(`e.rip=${address};e.lastSize=${size};`);
        else parts.push(`executed=${i + 1};`);
      }
      if (this.engine.hasCodeHook(address)) {
        parts.push(`e.onCodeHook?.(${address},${size});if(e.stopRequested)return e.rip;`);
        parts.push(
          `if(e.rip!==${address}||e.jit.epoch!==epoch){const p=e.rip;e.rip=e.step();e.onPostStep?.(p,e.lastSize);return e.rip;}`,
        );
      }
      if (observable) parts.push('e.insnCount++;');
      const { prologue, body } = this.emitShared(instruction, versions, shared, spans);
      // Observers may change registers or mappings between instructions: re-derive every span.
      if (observable) versions.clear();
      parts.push(prologue + body);
      if (this.observed) {
        parts.push(`e.rip=${target ?? next};e.onPostStep?.(${address},${size});`);
        if (target !== undefined) parts.push('return e.rip;');
        else parts.push(`if(e.stopRequested||e.jit.epoch!==epoch||e.rip!==${next})return e.rip;`);
      } else if (target !== undefined) {
        parts.push(`return ${target};`);
      }
      if (writes) parts.push(`if(e.jit.epoch!==epoch)return ${next};`);
    }
    const last = instructions[instructions.length - 1];
    parts.push(`return ${last.address + last.size};`);
    const generated = this.build(patchSpans(parts.join('\n'), spans), observable, shared);
    return {
      start: instructions[0].address,
      end: last.address + last.size,
      addresses: instructions.map((instruction) => instruction.address),
      instructions,
      observable,
      valid: true,
      next0: null,
      next1: null,
      targets: [],
      sites: generated.sites,
      run: generated.run,
      hits: 0,
      region: null,
    };
  }

  /**
   * Index-free operands of one base register share a single mapping check per block and
   * per register value: the first instruction using the register checks the whole span
   * covered by those operands, so a fault anywhere in the span is reported at that
   * instruction. Writes to the register end the span; later uses re-derive it.
   */
  private emitShared(
    instruction: Instruction,
    versions: Map<number, number>,
    shared: MemorySite[],
    spans: Span[],
  ): { prologue: string; body: string } {
    let prologue = '';
    for (const { base, disp, size } of instruction.shared) {
      let site = versions.get(base);
      if (site === undefined) {
        site = shared.length;
        shared.push({ base: Infinity, end: 0, bytes: null, view: null });
        spans.push({ min: Infinity, max: -Infinity });
        versions.set(base, site);
        prologue +=
          `B${site}=${low(base)}+${high(base)}*${U32};` +
          `if(B${site}/*MIN${site}*/<t${site}.base||B${site}/*MAX${site}*/>t${site}.end)e.refillSpan(t${site},B${site}/*MIN${site}*/,/*LEN${site}*/0);` +
          `O${site}=B${site}-t${site}.base;V${site}=t${site}.view;`;
      }
      const span = spans[site];
      span.min = Math.min(span.min, disp);
      span.max = Math.max(span.max, disp + size);
    }
    const body = instruction.body.replace(/\b([XYZ])(\d+)_/g, (_, kind: string, reg: string) => {
      const site = versions.get(Number(reg))!;
      return `${kind === 'X' ? 'V' : kind === 'Y' ? 'O' : 'B'}${site}`;
    });
    for (const match of instruction.body.matchAll(/\b[lh]\[(\d+)\]=(?![=])/g)) versions.delete(Number(match[1]));
    return { prologue, body };
  }

  private build(
    source: string,
    observable: boolean,
    shared: MemorySite[],
    region = false,
  ): { sites: MemorySite[]; run: JitBlock['run'] } {
    const spanLocals = shared.map((_, i) => `,B${i},O${i},V${i}`).join('');
    source = source.replace('let a,b,ah,bh,r,rh,t,c,m,n;', `let a,b,ah,bh,r,rh,t,c,m,n${spanLocals};`);
    if (!observable) {
      const registers = [
        ...new Set([...source.matchAll(/\b([lh])\[(\d+)\]/g)].map((match) => `${match[1]}${match[2]}`)),
      ];
      const modified = new Set(
        [...source.matchAll(/\b([lh])\[(\d+)\]=(?![=])/g)].map((match) => `${match[1]}${match[2]}`),
      );
      source = source.replace(/\b([lh])\[(\d+)\]/g, '$1$2');
      const declarations = registers
        .map((name) => `${name}=e.${name[0] === 'l' ? 'lo' : 'hi'}[${name.slice(1)}]`)
        .join(',');
      const stores = registers
        .filter((name) => modified.has(name))
        .map((name) => `e.${name[0] === 'l' ? 'lo' : 'hi'}[${name.slice(1)}]=${name};`)
        .join('');
      const locals = `let executed=0${region ? ',bb=0,pc=0' : ''}${declarations ? `,${declarations}` : ''};`;
      const fault = region ? 'e.jitFault(this.members[pc],executed-bb,x)' : 'e.jitFault(this,executed,x)';
      source = `${locals}try{${source}}catch(x){${fault};throw x;}finally{${stores}e.insnCount+=executed;}`;
    }
    const sites: MemorySite[] = [];
    const siteFor = (address: string, size: number) => {
      const name = `s${sites.length}`;
      sites.push({ base: Infinity, end: 0, bytes: null, view: null });
      return {
        name,
        check: `((${address})<${name}.base||(${address})+${size}>${name}.end)&&e.refill(${name},${address});`,
      };
    };
    source = source.replace(/([ab])=e\.read32\(m\);\1h=e\.read32\(m\+4\);/g, (_, variable) => {
      const { name, check } = siteFor('m', 8);
      return `${check}${variable}=${name}.view.getUint32(m-${name}.base,true);${variable}h=${name}.view.getUint32(m+4-${name}.base,true);`;
    });
    source = source.replace(/e\.read(8|16|32)\((m(?:\+4)?)\)/g, (_, bits, address) => {
      const { name, check } = siteFor(address, Number(bits) / 8);
      return `((${check.slice(0, -1)}),${name}.view.getUint${bits}((${address})-${name}.base,true))`;
    });
    const guard = (rip: string, address: string, value: string, size: number) =>
      `if(e.watchRanges.length||(${address})+${size}>e.jit.codeLow&&(${address})<e.jit.codeHigh){e.rip=${rip};e.noteWrite(${address},${value},${size});}`;
    source = source.replace(
      /\/\*W(\d+)\*\/e\.write(8|16|32)\((m(?:\+4)?),([^;]+)\);/g,
      (_, rip, bits, address, value) => {
        const size = Number(bits) / 8;
        const { name, check } = siteFor(address, size);
        return `${guard(rip, address, value, size)}${check}${name}.view.setUint${bits}((${address})-${name}.base,${value},true);`;
      },
    );
    source = source.replace(
      /\/\*W(\d+)\*\/e\.sw(8|16|32)\((\w+),([^,]+),(m(?:\+4)?),([^;]+)\);/g,
      (_, rip, bits, view, offset, address, value) =>
        `${guard(rip, address, value, Number(bits) / 8)}${view}.setUint${bits}(${offset},${value},true);`,
    );
    source = source
      .replace('const l=e.lo,h=e.hi,epoch=e.jit.epoch;', 'const J=e.jit,l=e.lo,h=e.hi,epoch=J.epoch;')
      .replace(/e\.jit\./g, 'J.')
      .replace(/\b4294967296\b/g, 'U')
      .replace(/Math\.floor\(/g, 'F(')
      .replace(/Math\.imul\(/g, 'I(');
    // Sites and helpers are closure constants: nothing is loaded per invocation.
    const bindings = [...sites.map((_, i) => `s${i}=sites[${i}]`), ...shared.map((_, i) => `t${i}=shared[${i}]`)].join(
      ',',
    );
    const factory = new Function(
      'sites',
      'shared',
      'mulHigh',
      `const U=4294967296,F=Math.floor,I=Math.imul${bindings ? `,${bindings}` : ''};return function ${region ? 'jitRegion' : 'jitBlock'}(e){${source}};`,
    );
    return { sites, run: factory(sites, shared, multiplyHigh) as JitBlock['run'] };
  }

  /** Static or observed successor addresses of a compiled block. */
  private successors(block: JitBlock): number[] {
    const last = block.instructions[block.instructions.length - 1];
    if (last.target === undefined) return [last.address + last.size];
    if (/^\d+$/.test(last.target)) return [Number(last.target)];
    const conditional = /^\((.*)\?(\d+):(\d+)\)$/.exec(last.target);
    if (conditional) return [Number(conditional[2]), Number(conditional[3])];
    const observed = [...block.targets];
    for (const next of [block.next0, block.next1]) {
      if (next?.valid && !observed.includes(next.start)) observed.push(next.start);
    }
    return observed;
  }

  /**
   * Compiles a hot block with its hot successors into one function. Members keep guest
   * registers in locals across block boundaries; indirect jumps resolve against every member.
   */
  buildRegion(head: JitBlock, until: number, seeds: number[] = [], generation = 0): JitRegion | null {
    if (head.observable || this.observed || this.regionsBuilt >= REGION_LIMIT) return null;
    const started = performance.now();
    const logging = this.executionLog !== null;
    const members: JitBlock[] = [head];
    const index = new Map<number, number>([[head.start, 0]]);
    const bodyLength = (block: JitBlock) =>
      block.instructions.reduce((n, instruction) => n + instruction.body.length, 0);
    let body = bodyLength(head);
    let total = head.addresses.length;
    // Best-first admission: seeds (in the given order) before the hottest reachable blocks, so the
    // hot path fills the size budget before lukewarm side paths do.
    const candidates = new Map<number, number>();
    const propose = (address: number, priority: number): void => {
      if (index.has(address) || candidates.has(address)) return;
      const block = this.blocks.get(address);
      if (!block || !block.valid || block.observable) return;
      if (priority < 0 && block.hits * 32 < head.hits) return;
      if (address === until || (until > block.start && until < block.end)) return;
      candidates.set(address, priority < 0 ? block.hits : priority);
    };
    seeds.forEach((seed, position) => propose(seed, Number.MAX_SAFE_INTEGER - position));
    for (const address of this.successors(head)) propose(address, -1);
    while (candidates.size && members.length < REGION_MAX_BLOCKS) {
      let best = -1;
      let bestPriority = -Infinity;
      for (const [address, priority] of candidates) {
        if (priority > bestPriority) {
          best = address;
          bestPriority = priority;
        }
      }
      candidates.delete(best);
      const block = this.blocks.get(best)!;
      if (body + bodyLength(block) > REGION_MAX_BODY) continue;
      index.set(best, members.length);
      members.push(block);
      body += bodyLength(block);
      total += block.addresses.length;
      for (const address of this.successors(block)) propose(address, -1);
    }
    const edge = (from: number, address: number): string => {
      const to = index.get(address);
      if (to === undefined) return `return ${address};`;
      return `${to <= from ? `if(executed>=${REGION_BUDGET})return ${address};` : ''}pc=${to};continue;`;
    };
    const shared: MemorySite[] = [];
    const spans: Span[] = [];
    const parts = [`${HEADER}${logging ? 'const M=this.members,L=e.jit.executionLog;' : ''}for(;;){switch(pc){`];
    members.forEach((block, position) => {
      parts.push(`case ${position}:{bb=executed;`);
      const versions = new Map<number, number>();
      const count = block.instructions.length;
      for (let i = 0; i < count; i++) {
        const instruction = block.instructions[i];
        const next = instruction.address + instruction.size;
        if (instruction.writes || instruction.memoryRead || i === count - 1) parts.push(`executed=bb+${i + 1};`);
        const emitted = this.emitShared(instruction, versions, shared, spans);
        parts.push(emitted.prologue + emitted.body);
        if (instruction.writes) {
          const log = logging ? `L.push({block:M[${position}],count:${i + 1}});` : '';
          parts.push(`if(e.jit.epoch!==epoch){${log}return ${next};}`);
        }
      }
      if (logging) parts.push(`L.push({block:M[${position}],count:${count}});`);
      const last = block.instructions[count - 1];
      const target = last.target;
      if (target === undefined) parts.push(edge(position, last.address + last.size));
      else if (/^\d+$/.test(target)) parts.push(edge(position, Number(target)));
      else {
        const conditional = /^\((.*)\?(\d+):(\d+)\)$/.exec(target);
        if (conditional) {
          parts.push(
            `if(${conditional[1]}){${edge(position, Number(conditional[2]))}}else{${edge(position, Number(conditional[3]))}}`,
          );
        } else {
          parts.push(`t=${target};`);
          const observed = this.successors(block).filter((address) => index.has(address));
          for (const address of observed) parts.push(`if(t===${address}){${edge(position, address)}}`);
          const rest = members.map((member) => member.start).filter((address) => !observed.includes(address));
          rest.sort((x, y) => x - y);
          const tree = (addresses: number[]): string => {
            if (addresses.length <= 2) {
              return addresses.map((address) => `if(t===${address}){${edge(position, address)}}`).join('');
            }
            const middle = addresses.length >> 1;
            return `if(t<${addresses[middle]}){${tree(addresses.slice(0, middle))}}else{${tree(addresses.slice(middle))}}`;
          };
          parts.push(tree(rest));
          parts.push('return t;');
        }
      }
      parts.push('}');
    });
    parts.push('}}');
    const generated = this.build(patchSpans(parts.join('\n'), spans), false, shared, true);
    const region: JitRegion = {
      start: head.start,
      members,
      index,
      epoch: this.epoch,
      until,
      logging,
      generation,
      exits: 0,
      executed: 0,
      exitTargets: new Map(),
      sites: generated.sites,
      run: generated.run,
      next0: null,
      next1: null,
      targets: [],
    };
    head.region = region;
    this.regionsBuilt++;
    this.regionInstructions += total;
    this.compilationMs += performance.now() - started;
    return region;
  }

  /** Rebuilds a region around the exits it takes most often, while it keeps exiting too early. */
  growRegion(region: JitRegion, until: number): void {
    const frequent = region.executed < region.exits * REGION_BUDGET;
    const hot = [...region.exitTargets]
      .filter(([address, count]) => count * 64 >= region.exits && !region.index.has(address))
      .filter(([address]) => this.blocks.get(address)?.valid)
      .sort((x, y) => y[1] - x[1])
      .map(([address]) => address);
    region.exits = 0;
    region.executed = 0;
    region.exitTargets.clear();
    if (!frequent || hot.length === 0) {
      region.generation = REGION_MAX_GENERATION;
      return;
    }
    const seeds = [...hot, ...region.members.slice(1).map((member) => member.start)];
    this.buildRegion(region.members[0], until, seeds, region.generation + 1);
  }

  private decode(address: number): Instruction | null {
    const e = this.engine;
    const size = e.insnLength(address);
    const end = address + size;
    let p = address;
    let rex = 0;
    let width = 4;
    let addressWidth = 8;
    for (;;) {
      const byte = e.read8(p);
      if (byte === 0x66) width = 2;
      else if (byte === 0x67) addressWidth = 4;
      else if (byte >= 0x40 && byte <= 0x4f) {
        rex = byte;
        if (byte & 8) width = 8;
      } else if ([0x2e, 0x36, 0x3e, 0x26].includes(byte)) {
        // Segment overrides used for alignment NOPs do not change the flat guest map.
      } else break;
      p++;
    }
    const op = e.read8(p++);
    if ([0xf0, 0xf2, 0xf3, 0x64, 0x65].includes(op)) return null;
    let body = '';
    let writes = false;
    let memoryRead = false;
    let flagsRead = 0;
    let flagsWritten = 0;
    let target: string | undefined;
    const shared: SharedAccess[] = [];
    const reg = (index: number): Operand => ({ reg: index });
    const immediate = (bytes: number, signed = false): number => {
      let value = 0;
      for (let i = 0; i < bytes; i++) value += e.read8(p++) * 2 ** (i * 8);
      return signed && value >= 2 ** (bytes * 8 - 1) ? value - 2 ** (bytes * 8) : value;
    };
    const rm = (): { operand: Operand; index: number; group: number } => {
      const modrm = e.read8(p++);
      const mod = modrm >>> 6;
      const index = ((modrm >>> 3) & 7) | (rex & 4 ? 8 : 0);
      const number = (modrm & 7) | (rex & 1 ? 8 : 0);
      if (mod === 3) return { operand: reg(number), index, group: (modrm >>> 3) & 7 };
      let base = number;
      let scaled = -1;
      let scale = 1;
      let disp = 0;
      let rip = false;
      if ((number & 7) === 4) {
        const sib = e.read8(p++);
        scale = 1 << (sib >>> 6);
        if (((sib >>> 3) & 7) !== 4 || rex & 2) scaled = ((sib >>> 3) & 7) | (rex & 2 ? 8 : 0);
        base = (sib & 7) | (rex & 1 ? 8 : 0);
        if ((sib & 7) === 5 && mod === 0) {
          base = -1;
          disp = immediate(4, true);
        }
      } else if ((number & 7) === 5 && mod === 0) {
        base = -1;
        rip = true;
        disp = immediate(4, true);
      }
      if (mod === 1) disp = immediate(1, true);
      if (mod === 2) disp = immediate(4, true);
      const lower = [String(disp + (rip ? end : 0))];
      const upper: string[] = [];
      const plain = [String(disp + (rip ? end : 0))];
      if (base >= 0) {
        lower.push(low(base));
        upper.push(high(base));
        plain.push(`${low(base)}+${high(base)}*${U32}`);
      }
      if (scaled >= 0) {
        lower.push(`${low(scaled)}*${scale}`);
        upper.push(`${high(scaled)}*${scale}`);
      }
      // Half arithmetic is exact even when encoded pointers cancel modulo 2^64.
      const sum = lower.join('+');
      const upperSum = upper.length ? upper.join('+') : '0';
      const lowerHalf = `((${sum})>>>0)`;
      const upperHalf = addressWidth === 4 ? '0' : `(((${upperSum})+Math.floor((${sum})/${U32}))>>>0)`;
      // Index-free operands cannot wrap into mapped memory: a plain double sum is exact for them.
      const expression =
        addressWidth === 4 ? lowerHalf : scaled < 0 ? `(${plain.join('+')})` : `(${lowerHalf}+${upperHalf}*${U32})`;
      const operand: Operand = { address: expression, lower: lowerHalf, upper: upperHalf };
      if (addressWidth === 8 && base >= 0 && scaled < 0) operand.shared = { base, disp };
      return { operand, index, group: (modrm >>> 3) & 7 };
    };
    // Shared operands read through the span view: X<reg>_ is the view, Y<reg>_ the offset, Z<reg>_ the address.
    const read = (operand: Operand, bits: number, variable = 'a'): string => {
      if ('reg' in operand) {
        const index = operand.reg;
        if (bits === 8) return `${variable}=${low(index)};${variable}h=${high(index)};`;
        if (bits === 4) return `${variable}=${low(index)};`;
        if (bits === 2) return `${variable}=${low(index)}&65535;`;
        return `${variable}=${!rex && index >= 4 && index < 8 ? `(${low(index & 3)}>>>8)` : low(index)}&255;`;
      }
      memoryRead = true;
      if (operand.shared) {
        const { base, disp } = operand.shared;
        shared.push({ base, disp, size: bits });
        if (bits === 8) {
          return `${variable}=X${base}_.getUint32(Y${base}_${signed(disp)},true);${variable}h=X${base}_.getUint32(Y${base}_${signed(disp + 4)},true);`;
        }
        return `${variable}=X${base}_.getUint${bits * 8}(Y${base}_${signed(disp)},true);`;
      }
      return `m=${operand.address};${variable}=e.read${Math.min(bits, 4) * 8}(m);${bits === 8 ? `${variable}h=e.read32(m+4);` : ''}`;
    };
    const store = (operand: Operand, bits: number, value = 'r', upper = 'rh'): string => {
      if ('reg' in operand) {
        const index = operand.reg;
        if (bits === 8) return `${low(index)}=(${value})>>>0;${high(index)}=(${upper})>>>0;`;
        if (bits === 4) return `${low(index)}=(${value})>>>0;${high(index)}=0;`;
        if (bits === 2) return `${low(index)}=((${low(index)}&4294901760)|(${value}&65535))>>>0;`;
        if (!rex && index >= 4 && index < 8)
          return `${low(index & 3)}=((${low(index & 3)}&4294902015)|((${value}&255)<<8))>>>0;`;
        return `${low(index)}=((${low(index)}&4294967040)|(${value}&255))>>>0;`;
      }
      writes = true;
      if (operand.shared) {
        const { base, disp } = operand.shared;
        shared.push({ base, disp, size: bits });
        const first = `m=Z${base}_${signed(disp)};/*W${address}*/e.sw${Math.min(bits, 4) * 8}(X${base}_,Y${base}_${signed(disp)},m,${value});`;
        return bits === 8
          ? `${first}/*W${address}*/e.sw32(X${base}_,Y${base}_${signed(disp + 4)},m+4,${upper});`
          : first;
      }
      return `m=${operand.address};/*W${address}*/e.write${Math.min(bits, 4) * 8}(m,${value});${bits === 8 ? `/*W${address}*/e.write32(m+4,${upper});` : ''}`;
    };
    const literal = (value: number, bits: number, variable = 'b'): string =>
      `${variable}=${value >>> 0};${bits === 8 ? `${variable}h=${value < 0 ? 4294967295 : Math.floor(value / U32)};` : ''}`;
    const flags = (bits: number, logical: boolean, subtract: boolean): string => {
      const mask = bits === 1 ? 255 : bits === 2 ? 65535 : 4294967295;
      const sign = bits === 1 ? 128 : bits === 2 ? 32768 : 2147483648;
      const common = `e.zf=+((${bits === 8 ? '(r|rh)' : 'r'})===0);e.sf=${bits === 8 ? 'rh>>>31' : `+((r&${sign})!==0)`};e.pf=(38505>>>((r^(r>>>4))&15))&1;`;
      if (logical) return `/*flags*/e.cf=0;e.of=0;e.af=0;${common}/*endflags*/`;
      const cf =
        bits === 8
          ? subtract
            ? '(ah<bh||(ah===bh&&a<b+c))'
            : `(ah+bh+((a+b+c)>=${U32}?1:0)>4294967295)`
          : subtract
            ? '(a<b+c)'
            : `(a+b+c>${mask})`;
      const operands = bits === 8 ? ['ah', 'bh', 'rh'] : ['a', 'b', 'r'];
      const [a, b, r] = operands;
      return `/*flags*/e.cf=+${cf};e.of=+((${subtract ? `(${a}^${b})` : `~(${a}^${b})`}&(${a}^${r})&${sign})!==0);e.af=+(((a^b^r)&16)!==0);${common}/*endflags*/`;
    };
    const alu = (kind: number, destination: Operand, source: Operand | number, bits: number, write = true): void => {
      flagsWritten = ALL_FLAGS;
      if (kind === 2 || kind === 3) flagsRead |= 1;
      body += read(destination, bits);
      body += typeof source === 'number' ? literal(source, bits) : read(source, bits, 'b');
      const logical = [1, 4, 6].includes(kind);
      const subtract = [3, 5, 7].includes(kind);
      body += `c=${kind === 2 || kind === 3 ? 'e.cf' : '0'};`;
      if (logical) {
        const operator = kind === 1 ? '|' : kind === 4 ? '&' : '^';
        body += `r=(a${operator}b)>>>0;${bits === 8 ? `rh=(ah${operator}bh)>>>0;` : ''}`;
      } else {
        body += `r=(a${subtract ? '-b-c' : '+b+c'})>>>0;`;
        if (bits === 8) body += `rh=(ah${subtract ? '-bh-(a<b+c?1:0)' : `+bh+(a+b+c>=${U32}?1:0)`})>>>0;`;
      }
      if (bits < 4) body += `r&=${bits === 1 ? 255 : 65535};b&=${bits === 1 ? 255 : 65535};`;
      body += flags(bits, logical, subtract);
      if (write && kind !== 7) body += store(destination, bits);
    };
    const move = (destination: Operand, source: Operand | number, bits: number): void => {
      body += typeof source === 'number' ? literal(source, bits, 'a') : read(source, bits);
      body += store(destination, bits, 'a', 'ah');
    };
    // The stack pointer is a shared base too: pushes write below the old value, pops read at it.
    const push = (operand: Operand | number): void => {
      body += typeof operand === 'number' ? literal(operand, 8, 'a') : read(operand, 8);
      shared.push({ base: 4, disp: -8, size: 8 });
      body += `m=Z4_-8;/*W${address}*/e.sw32(X4_,Y4_-8,m,a);/*W${address}*/e.sw32(X4_,Y4_-4,m+4,ah);${low(4)}=m>>>0;${high(4)}=Math.floor(m/${U32});`;
      writes = true;
    };
    const pop = (adjust: number): void => {
      shared.push({ base: 4, disp: 0, size: 8 });
      memoryRead = true;
      body += `a=X4_.getUint32(Y4_+0,true);ah=X4_.getUint32(Y4_+4,true);m=${low(4)}+${high(4)}*${U32}+${8 + adjust};${low(4)}=m>>>0;${high(4)}=Math.floor(m/${U32});`;
    };
    if (op < 0x40 && (op & 7) < 6) {
      const form = op & 7;
      const kind = op >>> 3;
      const bits = form === 0 || form === 2 || form === 4 ? 1 : width;
      if (form < 4) {
        const { operand, index } = rm();
        alu(kind, form < 2 ? operand : reg(index), form < 2 ? reg(index) : operand, bits);
      } else alu(kind, reg(0), immediate(bits === 8 ? 4 : bits, bits === 8), bits);
    } else if (op >= 0x50 && op <= 0x57) push(reg((op & 7) | (rex & 1 ? 8 : 0)));
    else if (op >= 0x58 && op <= 0x5f) {
      pop(0);
      body += store(reg((op & 7) | (rex & 1 ? 8 : 0)), 8, 'a', 'ah');
    } else if (op >= 0x70 && op <= 0x7f) {
      target = `(${conditions[op & 15]}?${end + immediate(1, true)}:${end})`;
      flagsRead |= CONDITION_FLAGS[op & 15];
    } else if (op >= 0xb0 && op <= 0xbf) {
      const bits = op < 0xb8 ? 1 : width;
      const index = (op & 7) | (rex & 1 ? 8 : 0);
      if (bits === 8) {
        const lower = immediate(4);
        const upper = immediate(4);
        body = `${low(index)}=${lower};${high(index)}=${upper};`;
      } else move(reg(index), immediate(bits), bits);
    } else
      switch (op) {
        case 0x63: {
          const { operand, index } = rm();
          body += read(operand, 4);
          body += store(reg(index), width, 'a', '(a&2147483648?4294967295:0)');
          break;
        }
        case 0x68:
          push(immediate(4, true));
          break;
        case 0x6a:
          push(immediate(1, true));
          break;
        case 0x69:
        case 0x6b: {
          if (width === 2) return null;
          const { operand, index } = rm();
          body += read(operand, width);
          body += literal(immediate(op === 0x69 ? 4 : 1, true), width);
          body += 'r=Math.imul(a,b)>>>0;';
          if (width === 8) body += 'rh=(mulHigh(a,b)+Math.imul(ah,b)+Math.imul(bh,a))>>>0;';
          body += store(reg(index), width);
          break;
        }
        case 0x80:
        case 0x81:
        case 0x83: {
          const { operand, group } = rm();
          const bits = op === 0x80 ? 1 : width;
          const imm = immediate(op === 0x81 ? Math.min(bits, 4) : 1, op === 0x83 || bits === 8);
          alu(group, operand, imm, bits);
          break;
        }
        case 0x84:
        case 0x85: {
          const { operand, index } = rm();
          alu(4, operand, reg(index), op === 0x84 ? 1 : width, false);
          break;
        }
        case 0x88:
        case 0x89:
        case 0x8a:
        case 0x8b: {
          const { operand, index } = rm();
          const bits = op & 1 ? width : 1;
          move(op < 0x8a ? operand : reg(index), op < 0x8a ? reg(index) : operand, bits);
          break;
        }
        case 0x8d: {
          const { operand, index } = rm();
          if ('reg' in operand) return null;
          // Read both halves before writing a destination that may also be a base/index.
          body += `a=${operand.lower};ah=${operand.upper};`;
          body += store(reg(index), width, 'a', 'ah');
          break;
        }
        case 0x90:
          break;
        case 0x98:
          body += width === 8 ? 'h[0]=(l[0]&2147483648)?4294967295:0;' : 'l[0]=((l[0]<<16)>>16)>>>0;h[0]=0;';
          break;
        case 0x99:
          body +=
            width === 8 ? 'l[2]=h[2]=(h[0]&2147483648)?4294967295:0;' : 'l[2]=(l[0]&2147483648)?4294967295:0;h[2]=0;';
          break;
        case 0xc0:
        case 0xc1:
        case 0xd0:
        case 0xd1:
        case 0xd2:
        case 0xd3: {
          const { operand, group } = rm();
          if (group === 2 || group === 3) return null;
          flagsRead = ALL_FLAGS;
          const bits = op & 1 ? width : 1;
          const bitCount = bits * 8;
          const count = op < 0xd0 ? String(immediate(1)) : op < 0xd2 ? '1' : low(1);
          body += read(operand, bits);
          body += `c=(${count})&${bits === 8 ? 63 : 31};`;
          if (group < 2) body += `c%= ${bitCount};`;
          body += 'r=a;rh=ah;if(c!==0){';
          if (bits === 8) {
            if (group === 0)
              body +=
                'if(c<32){r=((a<<c)|(ah>>>(32-c)))>>>0;rh=((ah<<c)|(a>>>(32-c)))>>>0;}else if(c===32){r=ah;rh=a;}else{r=((ah<<(c-32))|(a>>>(64-c)))>>>0;rh=((a<<(c-32))|(ah>>>(64-c)))>>>0;}e.cf=r&1;';
            else if (group === 1)
              body +=
                'if(c<32){r=((a>>>c)|(ah<<(32-c)))>>>0;rh=((ah>>>c)|(a<<(32-c)))>>>0;}else if(c===32){r=ah;rh=a;}else{r=((ah>>>(c-32))|(a<<(64-c)))>>>0;rh=((a>>>(c-32))|(ah<<(64-c)))>>>0;}e.cf=rh>>>31;';
            else if (group === 4 || group === 6)
              body +=
                'if(c<32){r=(a<<c)>>>0;rh=((ah<<c)|(a>>>(32-c)))>>>0;e.cf=(ah>>>(32-c))&1;}else if(c===32){r=0;rh=a;e.cf=ah&1;}else{r=0;rh=(a<<(c-32))>>>0;e.cf=(a>>>(64-c))&1;}';
            else
              body += `if(c<32){r=((a>>>c)|(ah<<(32-c)))>>>0;rh=(ah${group === 7 ? '>>' : '>>>'}c)>>>0;e.cf=(a>>>(c-1))&1;}else{r=(ah${group === 7 ? '>>' : '>>>'}(c-32))>>>0;rh=${group === 7 ? '(ah>>31)>>>0' : '0'};e.cf=c===32?a>>>31:(ah>>>(c-33))&1;}`;
          } else {
            const mask = bits === 1 ? 255 : bits === 2 ? 65535 : 4294967295;
            if (group === 0) body += `r=(((a<<c)|(a>>>(${bitCount}-c)))&${mask})>>>0;e.cf=r&1;`;
            else if (group === 1)
              body += `r=(((a>>>c)|(a<<(${bitCount}-c)))&${mask})>>>0;e.cf=(r>>>${bitCount - 1})&1;`;
            else if (group === 4 || group === 6)
              body += `r=c>=${bitCount}?0:((a<<c)&${mask})>>>0;e.cf=c>${bitCount}?0:(a>>>(${bitCount}-c))&1;`;
            else if (group === 5) body += `r=c>=${bitCount}?0:a>>>c;e.cf=c>${bitCount}?0:(a>>>(c-1))&1;`;
            else
              body += `r=((((a<<${32 - bitCount})>>${32 - bitCount})>>c)&${mask})>>>0;e.cf=c>=${bitCount}?(a>>>${bitCount - 1})&1:(a>>>(c-1))&1;`;
          }
          if (group >= 4)
            body += `e.zf=+((${bits === 8 ? '(r|rh)' : 'r'})===0);e.sf=${bits === 8 ? 'rh>>>31' : `(r>>>${bitCount - 1})&1`};t=r&255;t^=t>>>4;t^=t>>>2;e.pf=(t^(t>>>1)^1)&1;`;
          body += `if(c===1){e.of=${group === 1 ? (bits === 8 ? '(rh>>>31)^((rh>>>30)&1)' : `(r>>>${bitCount - 1})^((r>>>${bitCount - 2})&1)`) : group === 5 ? (bits === 8 ? 'ah>>>31' : `(a>>>${bitCount - 1})&1`) : group === 7 ? '0' : `${bits === 8 ? '(rh>>>31)' : `(r>>>${bitCount - 1})`}^e.cf`};}}`;
          body += store(operand, bits);
          break;
        }
        case 0xf6:
        case 0xf7: {
          const { operand, group } = rm();
          const bits = op === 0xf6 ? 1 : width;
          if (group === 0) alu(4, operand, immediate(Math.min(bits, 4), bits === 8), bits, false);
          else if (group === 2) {
            body += read(operand, bits);
            body += store(operand, bits, '~a', '~ah');
          } else if (group === 3) {
            flagsWritten = ALL_FLAGS;
            body += read(operand, bits, 'b');
            body += 'a=0;ah=0;c=0;r=(-b)>>>0;rh=(-bh-(b?1:0))>>>0;';
            if (bits < 4) body += `r&=${bits === 1 ? 255 : 65535};`;
            body += flags(bits, false, true);
            body += store(operand, bits);
          } else if ((group === 4 || group === 5) && bits < 8) {
            flagsWritten = 33;
            body += read(operand, bits);
            body += read(reg(0), bits, 'b');
            if (bits === 4) {
              body += 'r=Math.imul(a,b)>>>0;rh=mulHigh(a,b);';
              if (group === 5) body += 'rh=(rh-(a&2147483648?b:0)-(b&2147483648?a:0))>>>0;';
              body += store(reg(0), 4);
              body += store(reg(2), 4, 'rh');
              body += `e.cf=e.of=+(rh!==${group === 5 ? '(r&2147483648?4294967295:0)' : '0'});`;
            } else {
              if (group === 5)
                body += `a=(a<<${32 - bits * 8})>>${32 - bits * 8};b=(b<<${32 - bits * 8})>>${32 - bits * 8};`;
              body += 'r=a*b;';
              body += store(reg(0), 2, 'r');
              if (bits === 2) body += store(reg(2), 2, '(r>>>16)');
              body += `e.cf=e.of=+(${group === 5 ? `(r<${-(2 ** (bits * 8 - 1))}||r>${2 ** (bits * 8 - 1) - 1})` : `r>${2 ** (bits * 8) - 1}`});`;
            }
          } else return null;
          break;
        }
        case 0xa8:
        case 0xa9: {
          const bits = op === 0xa8 ? 1 : width;
          alu(4, reg(0), immediate(Math.min(bits, 4), bits === 8), bits, false);
          break;
        }
        case 0xc6:
        case 0xc7: {
          const { operand, group } = rm();
          if (group !== 0) return null;
          const bits = op === 0xc6 ? 1 : width;
          move(operand, immediate(Math.min(bits, 4), bits === 8), bits);
          break;
        }
        case 0xc3:
        case 0xc2: {
          pop(op === 0xc2 ? immediate(2) : 0);
          target = `a+ah*${U32}`;
          break;
        }
        case 0xe8: {
          const dest = end + immediate(4, true);
          push(end);
          target = String(dest);
          break;
        }
        case 0xe9:
          target = String(end + immediate(4, true));
          break;
        case 0xeb:
          target = String(end + immediate(1, true));
          break;
        case 0xfe:
        case 0xff: {
          const { operand, group } = rm();
          if (group < 2) {
            body += 'n=e.cf;';
            alu(group === 0 ? 0 : 5, operand, 1, op === 0xfe ? 1 : width);
            body += 'e.cf=n;';
            flagsWritten &= ~1;
            flagsRead |= 1;
          } else if (op === 0xff && (group === 2 || group === 4)) {
            body += read(operand, 8);
            body += `n=a+ah*${U32};`;
            if (group === 2) push(end);
            target = 'n';
          } else if (op === 0xff && group === 6) push(operand);
          else return null;
          break;
        }
        case 0x0f: {
          const second = e.read8(p++);
          if ((second >= 0x40 && second <= 0x4f) || (second >= 0x80 && second <= 0x9f)) {
            flagsRead |= CONDITION_FLAGS[second & 15];
          }
          if (second >= 0x80 && second <= 0x8f)
            target = `(${conditions[second & 15]}?${end + immediate(4, true)}:${end})`;
          else if (second >= 0x90 && second <= 0x9f) {
            const { operand } = rm();
            body += store(operand, 1, `+(${conditions[second & 15]})`);
          } else if (second >= 0x40 && second <= 0x4f) {
            const { operand, index } = rm();
            body += `if(${conditions[second & 15]}){${read(operand, width)}${store(reg(index), width, 'a', 'ah')}}`;
          } else if ([0xb6, 0xb7, 0xbe, 0xbf].includes(second)) {
            const { operand, index } = rm();
            const bits = second & 1 ? 2 : 1;
            body += read(operand, bits);
            if (second & 8) body += `a=(a<<${32 - bits * 8})>>${32 - bits * 8};`;
            body += store(reg(index), width, 'a', '(a<0?4294967295:0)');
          } else if (second === 0xaf && width !== 2) {
            const { operand, index } = rm();
            body += read(operand, width);
            body += read(reg(index), width, 'b');
            body += 'r=Math.imul(a,b)>>>0;';
            if (width === 8) body += 'rh=(mulHigh(a,b)+Math.imul(ah,b)+Math.imul(bh,a))>>>0;';
            body += store(reg(index), width);
          } else if (second >= 0x18 && second <= 0x1f) rm();
          else return null;
          break;
        }
        default:
          return null;
      }
    if (p !== end) return null;
    memoryRead ||= body.includes('e.read');
    return { address, size, body, target, writes, memoryRead, flagsRead, flagsWritten, shared };
  }
}

interface Span {
  min: number;
  max: number;
}

/** Fills in the span bounds of shared base-register checks once every use is known. */
function patchSpans(source: string, spans: Span[]): string {
  return source.replace(/\/\*(MIN|MAX|LEN)(\d+)\*\/(0)?/g, (_, kind: string, index: string) => {
    const span = spans[Number(index)];
    if (kind === 'LEN') return String(span.max - span.min);
    return signed(kind === 'MIN' ? span.min : span.max);
  });
}
