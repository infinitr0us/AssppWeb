// @vitest-environment node
import { appendFileSync, readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { TsX86Engine, X86_REG } from '../../src/apple/kbsync/tsx86';

const CODE = 0x1000;
const DATA = 0x4000;
const STACK = 0x500000008000;
const recordOutput = process.env.KBSYNC_X86_FIXTURE_RECORD;
const referenceCases: Record<string, string> = recordOutput
  ? {}
  : JSON.parse(readFileSync(new URL('./fixtures/x86-reference.json', import.meta.url), 'utf8')).cases;

function qword(value: bigint): number[] {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt.asUintN(64, value), true);
  return [...bytes];
}

const bytes = (hex: string) =>
  hex
    .trim()
    .split(/\s+/)
    .map((byte) => parseInt(byte, 16));

async function compare(code: number[], flagsMask = 0, count = 1000): Promise<void> {
  const actual = [new TsX86Engine(), new TsX86Engine({ jit: true })];
  // Store full registers as bytes; the reference numeric API rounds above 2^53.
  const program = Uint8Array.from([
    ...code,
    ...bytes('48 89 07 48 89 4f 08 48 89 57 10 48 89 77 18 4c 89 47 20 4c 89 4f 28'),
    ...bytes('9c 58 48 89 47 30'),
  ]);
  const key = Buffer.from(program).toString('hex');
  const run = (engine: Pick<TsX86Engine, 'memMap' | 'memWrite' | 'regWrite' | 'emuStart' | 'regRead' | 'memRead'>) => {
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memMap(STACK, 0x1000);
    engine.memWrite(CODE, program);
    engine.memWrite(DATA + 0x80, Uint8Array.from([...qword(0xfedcba9876543210n), ...qword(0x0123456789abcdefn)]));
    engine.regWrite(X86_REG.RDI, DATA);
    engine.regWrite(X86_REG.RSI, DATA + 0x80);
    engine.regWrite(X86_REG.RSP, STACK + 0x800);
    engine.emuStart(CODE, CODE + program.length, 1_000_000, count);
    expect(engine.regRead(X86_REG.RIP)).toBe(CODE + program.length);
    return engine.memRead(DATA, 0x100);
  };
  const masked = (result: Uint8Array) => {
    const view = new DataView(result.buffer, result.byteOffset, result.byteLength);
    view.setBigUint64(0x30, view.getBigUint64(0x30, true) & BigInt(flagsMask), true);
    return Buffer.from(result).toString('hex');
  };
  try {
    let expected: Uint8Array;
    if (recordOutput) {
      const { openUnicornReference } = await import('./unicorn-reference.mjs');
      const reference = await openUnicornReference();
      try {
        expected = run(reference);
        appendFileSync(
          recordOutput,
          JSON.stringify({ program: key, output: Buffer.from(expected).toString('base64') }) + '\n',
        );
      } finally {
        reference.close();
      }
    } else {
      if (!referenceCases[key]) {
        throw new Error(
          `Missing x86 reference fixture for ${key}; run record-x86-fixtures.mjs with the external oracle`,
        );
      }
      expected = Buffer.from(referenceCases[key], 'base64');
    }
    const expectedHex = masked(expected);
    for (const engine of actual) expect(masked(run(engine))).toBe(expectedHex);
  } finally {
    for (const engine of actual) engine.close();
  }
}

const values = [
  [0x0123456789abcdefn, 0xfedcba9876543210n],
  [0xffffffffffffffffn, 1n],
  [0x7fffffffffffffffn, 1n],
  [0x100000000n, 0x100000000n],
];

describe('TS x86 instruction regressions against recorded reference', () => {
  for (const [a, b] of values) {
    const setup = [0x48, 0xb8, ...qword(a), 0x48, 0xb9, ...qword(b)];
    describe(`${a.toString(16)}, ${b.toString(16)}`, () => {
      it.each([
        ['add', '48 01 c8', 0x8d5],
        ['adc', 'f9 48 11 c8', 0x8d5],
        ['sub', '48 29 c8', 0x8d5],
        ['sbb', 'f9 48 19 c8', 0x8d5],
        ['cmp', '48 39 c8', 0x8d5],
        ['and', '48 21 c8', 0x8c5],
        ['or', '48 09 c8', 0x8c5],
        ['xor', '48 31 c8', 0x8c5],
        ['test', '48 85 c8', 0x8c5],
        ['inc', '48 ff c0', 0x8d5],
        ['dec', '48 ff c8', 0x8d5],
        ['neg', '48 f7 d8', 0x8d5],
        ['not', '48 f7 d0', 0],
        ['mul', '48 f7 e1', 0x801],
        ['imul', '48 f7 e9', 0x801],
        ['byte mul flags', 'f6 e1', 0x801],
        ['byte imul flags', 'f6 e9', 0x801],
        ['word mul flags', '66 f7 e1', 0x801],
        ['word imul flags', '66 f7 e9', 0x801],
        ['dword mul flags', 'f7 e1', 0x801],
        ['dword imul flags', 'f7 e9', 0x801],
        ['imul low qword', '48 0f af c1', 0],
        ['imul signed imm32', '48 69 c0 43 21 65 87', 0],
        ['imul signed imm8', '48 6b c0 87', 0],
        ['lea', '48 8d 04 48', 0],
        ['stack', '50 59', 0],
        ['memory', '48 89 46 08 48 8b 4e 08', 0],
        ['cmov', '48 39 c0 48 0f 44 c1', 0],
        ['xchg', '48 87 c8', 0],
        ['xchg accumulator', '48 91', 0],
        ['push r/m', 'ff f0 59', 0],
        ['test imm accumulator', '48 a9 ff ff ff ff', 0x8c5],
        ['test imm group', '48 f7 c0 ff ff ff ff', 0x8c5],
        ['bswap', '48 0f c8', 0],
        ['xadd', '48 0f c1 c8', 0x8d5],
        ['word write', '66 b8 34 12', 0],
        ['byte write', 'b4 12', 0],
        ['REX byte write', '40 b6 12', 0],
      ])('%s', async (_, instruction, mask) => compare([...setup, ...bytes(instruction)], mask));

      for (const count of [0, 1, 31, 32, 63, 64]) {
        it.each([
          ['rol', 0xc0],
          ['ror', 0xc8],
          ['rcl', 0xd0],
          ['rcr', 0xd8],
          ['shl', 0xe0],
          ['shr', 0xe8],
          ['sar', 0xf8],
        ])(`%s by ${count}`, async (_, modrm) => {
          await compare([...setup, 0xf9, 0x48, 0xc1, modrm, count], count === 1 ? 0x801 : 1);
        });
      }
    });
  }

  it.each([
    ['sign-extended imm8', '48 c7 c0 13 00 00 00 48 83 c0 ed'],
    ['sign-extended imm32', '48 c7 c0 ff ff ff ff'],
    ['negative LEA to a dword', 'b8 57 8d 8d 15 8d 80 6a 30 09 9f'],
    ['RIP-relative store with immediate', 'c7 05 00 00 00 00 90 90 90 90 90 90 90 90'],
    ['15-byte NOP', '66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00'],
    ['near conditional jump length', '31 c0 0f 84 00 00 00 00'],
    ['byte MUL preserves RDX and writes AX', '48 ba 88 77 66 55 44 33 22 11 b0 f3 b1 a7 f6 e1'],
    ['byte IMUL writes AX', 'b0 f3 b1 a7 f6 e9'],
    ['byte DIV reads AX', '66 b8 23 01 b1 13 f6 f1'],
    ['byte IDIV reads signed AX', '66 b8 dd fe b1 13 f6 f9'],
    ['qword DIV high product', '48 b8 ff ff ff ff ff ff ff 7f 48 c7 c1 03 00 00 00 48 f7 e1 48 f7 f1'],
    ['qword IDIV signed dividend', '48 c7 c0 f9 ff ff ff 48 99 48 c7 c1 03 00 00 00 48 f7 f9'],
    ['SHRD', 'b8 78 56 34 12 b9 21 43 65 87 0f ac c8 05'],
    ['SHLD', 'b8 78 56 34 12 b9 21 43 65 87 0f a4 c8 05'],
    ['XMM load, XOR and stores', '0f 28 06 0f 28 c8 0f 57 c1 0f 29 46 10 0f 29 4e 20'],
    ['negative push immediate', '6a ff 59 68 fe ff ff ff 58'],
    ['CDQE', 'b8 fe ff ff ff 48 98'],
    ['MOVSQ preserves all bits', '49 89 f8 48 8d 7e 20 48 a5 4c 89 c7'],
    ['STOSQ preserves all bits', '49 89 f8 48 8d 7e 20 48 8b 06 48 ab 4c 89 c7'],
    ['LODSQ preserves all bits', '48 ad'],
    ['CMPSQ compares high bits', '49 89 f8 48 8d 7e 08 48 a7 4c 89 c7'],
    ['SCASQ compares high bits', '49 89 f8 48 8d 7e 08 48 8b 06 48 af 4c 89 c7'],
    ['PUSH RSP r/m saves original RSP', 'ff f4 58'],
    ['PUSH RSP saves original RSP', '54 58'],
    ['BSF high-only qword', '48 b8 00 00 00 00 00 00 00 80 48 0f bc c8'],
    ['BSR high-only qword', '48 b8 00 00 00 00 00 00 00 80 48 0f bd c8'],
  ])('%s', async (_, program) => compare(bytes(program)));

  it.each([
    ['BT immediate', 'b8 03 00 00 00 0f ba e0 01'],
    ['BTS immediate', 'b8 00 00 00 00 0f ba e8 01'],
    ['BTR immediate', 'b8 03 00 00 00 0f ba f0 01'],
    ['BTC immediate', 'b8 03 00 00 00 0f ba f8 01'],
    ['BT register', 'b8 03 00 00 00 b9 21 00 00 00 0f a3 c8'],
    ['BTS register', 'b8 00 00 00 00 b9 21 00 00 00 0f ab c8'],
    ['BTR register', 'b8 03 00 00 00 b9 21 00 00 00 0f b3 c8'],
    ['BTC register', 'b8 03 00 00 00 b9 21 00 00 00 0f bb c8'],
    ['BT memory crossing qword', 'b9 40 00 00 00 48 0f a3 0e'],
    ['BT memory negative index', '48 c7 c1 ff ff ff ff 48 0f a3 0e'],
  ])('%s', async (_, program) => compare(bytes(program), 1));

  it.each([
    ['dword add carry', 'b8 ff ff ff ff 83 c0 01', 0x8d5],
    ['dword adc carry', 'b8 ff ff ff ff f9 83 d0 00', 0x8d5],
    ['word compare sign-extended immediate', '66 b8 ff ff 66 83 f8 ff', 0x8d5],
    ['byte compare unsigned immediate', 'b0 ff 80 f8 ff', 0x8d5],
    ['word xor sign-extended immediate', '66 b8 ff ff 66 83 f0 ff', 0x8c5],
  ])('%s', async (_, program, mask) => compare(bytes(program), mask));

  it('uses R12 as a SIB index with REX.X', async () => {
    await compare(bytes('b8 05 00 00 00 49 89 c4 4a 8d 0c 26'));
  });

  it.each([0, 1])('matches the reference CPU profile for CPUID leaf %i', async (leaf) => {
    await compare([
      ...bytes('48 bb ff ff ff ff ff ff ff ff 48 b9 ff ff ff ff ff ff ff ff 48 ba ff ff ff ff ff ff ff ff'),
      0x48,
      0xb8,
      ...qword(0xffffffff00000000n | BigInt(leaf)),
      ...bytes('0f a2 48 89 de'),
    ]);
  });

  it.each([false, true])('bounds a looping guest by instruction count and wall time (JIT=%s)', (jit) => {
    const engine = new TsX86Engine({ jit });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from([0xeb, 0xfe]));
    engine.emuStart(CODE, CODE + 2, 0, 10);
    expect(engine.instructionCount).toBe(10);
    const now = vi.spyOn(performance, 'now').mockReturnValueOnce(0).mockReturnValueOnce(0).mockReturnValue(2);
    try {
      expect(() => engine.emuStart(CODE, CODE + 2, 1000)).toThrow('execution timed out');
      expect(engine.instructionCount).toBe(4106);
    } finally {
      now.mockRestore();
    }
  });

  it('reports the current hook size and honors stop before executing', () => {
    const engine = new TsX86Engine();
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('48 c7 c0 01 00 00 00')));
    engine.addCodeHook(CODE, CODE + 7);
    engine.onCodeHook = (address, size) => {
      expect(address).toBe(CODE);
      expect(size).toBe(7);
      engine.emuStop();
    };
    engine.emuStart(CODE, CODE + 7);
    expect(engine.instructionCount).toBe(0);
    expect(engine.regRead(X86_REG.RAX)).toBe(0);
  });

  it('fails when the RDTSC recording is exhausted', () => {
    const engine = new TsX86Engine();
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('0f 31 0f 31')));
    engine.replayRdtsc([0x123456789]);
    expect(() => engine.emuStart(CODE, CODE + 4)).toThrow('RDTSC replay exhausted');
    expect(engine.regRead(X86_REG.RAX)).toBe(0x23456789);
    expect(engine.regRead(X86_REG.RDX)).toBe(1);
  });

  it('decodes near branches and a 15-byte NOP without extra block boundaries', () => {
    const engine = new TsX86Engine();
    engine.memMap(CODE, 0x1000);
    for (const [hex, length] of [
      ['0f 85 12 34 56 78', 6],
      ['66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00', 15],
      ['0f ac c8 05', 4],
    ] as const) {
      engine.memWrite(CODE, Uint8Array.from(bytes(hex)));
      expect(engine.insnLength(CODE)).toBe(length);
    }
  });
});

describe('JIT execution and cache boundaries', () => {
  it('invalidates cached immediates after a host write', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 01 00 00 00 83 c0 02')));
    engine.emuStart(CODE, CODE + 8, 0, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    expect(engine.jit!.compiledInstructions).toBe(2);
    engine.memWrite(CODE + 1, Uint8Array.of(9));
    engine.emuStart(CODE, CODE + 8, 0, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(11);
  });

  it('exits a block before executing instructions changed by a guest write', async () => {
    await compare(bytes('c7 05 01 00 00 00 2a 00 00 00 b8 01 00 00 00'));
  });

  it('uses updated code when a hook changes the current instruction', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 01 00 00 00')));
    engine.addCodeHook(CODE, CODE);
    let calls = 0;
    engine.onCodeHook = () => {
      calls++;
      engine.memWrite(CODE + 1, Uint8Array.of(42));
    };
    engine.emuStart(CODE, CODE + 5, 0, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(42);
    expect(calls).toBe(1);
    expect(engine.instructionCount).toBe(1);
  });

  it('observes each compiled instruction and stops before a hooked instruction', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 01 00 00 00 83 c0 02 83 c0 04')));
    const steps: number[] = [];
    engine.onPostStep = (pc) => steps.push(pc);
    engine.addCodeHook(CODE + 8, CODE + 8);
    engine.onCodeHook = () => engine.emuStop();
    engine.emuStart(CODE, CODE + 11);
    expect(steps).toEqual([CODE, CODE + 5]);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    expect(engine.instructionCount).toBe(2);
    expect(engine.jit!.compiledInstructions).toBe(2);
  });

  it('keeps hot linked loops identical to Unicorn', async () => {
    await compare(bytes('b9 10 27 00 00 31 c0 01 c8 83 e9 01 75 f9'), 0x8d5, 0);
  });

  it('compiles cold code only after repeated visits', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 07 00 00 00')));
    for (let i = 0; i < 3; i++) engine.emuStart(CODE, CODE + 5);
    expect(engine.jit!.compiledInstructions).toBe(0);
    engine.emuStart(CODE, CODE + 5);
    expect(engine.jit!.compiledInstructions).toBe(1);
    expect(engine.regRead(X86_REG.RAX)).toBe(7);
  });

  it('respects an until address inside a cached block and the instruction budget', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 01 00 00 00 83 c0 02 83 c0 04')));
    engine.jit!.get(CODE, CODE + 11);
    engine.emuStart(CODE, CODE + 8);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    engine.emuStart(CODE, CODE + 11, 0, 1);
    expect(engine.regRead(X86_REG.RIP)).toBe(CODE + 5);
    expect(engine.regRead(X86_REG.RAX)).toBe(1);
  });

  it('invalidates memory-site caches when a mapping is replaced', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('8b 06')));
    engine.regWrite(X86_REG.RSI, DATA);
    engine.memWrite(DATA, Uint8Array.of(3));
    engine.emuStart(CODE, CODE + 2, 0, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    engine.memUnmap(DATA, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memWrite(DATA, Uint8Array.of(9));
    engine.emuStart(CODE, CODE + 2, 0, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(9);
  });

  it('preserves watched writes through the optimized store path', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('c7 06 2a 00 00 00')));
    engine.regWrite(X86_REG.RSI, DATA);
    engine.watchRange(DATA, DATA + 4);
    engine.emuStart(CODE, CODE + 6, 0, 1000);
    expect(engine.watchLog).toEqual([{ rip: CODE, address: DATA, value: 42, size: 4 }]);
  });

  it('retains exact state when a compiled memory instruction faults', () => {
    for (const jit of [false, true]) {
      const engine = new TsX86Engine({ jit });
      engine.memMap(CODE, 0x1000);
      engine.memWrite(CODE, Uint8Array.from(bytes('b8 fe ff ff ff 83 c0 02 8b 16')));
      engine.regWrite(X86_REG.RSI, DATA);
      expect(() => engine.emuStart(CODE, CODE + 10, 0, 1000)).toThrow();
      expect(engine.regRead(X86_REG.RAX)).toBe(0);
      expect(engine.regRead(X86_REG.RIP)).toBe(CODE + 8);
      expect(engine.instructionCount).toBe(3);
    }
  });

  it('honors a post-step stop or code mutation before the next instruction', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('b8 01 00 00 00 83 c0 02')));
    engine.onPostStep = () => engine.emuStop();
    engine.emuStart(CODE, CODE + 8);
    expect(engine.regRead(X86_REG.RIP)).toBe(CODE + 5);
    expect(engine.regRead(X86_REG.RAX)).toBe(1);
    engine.onPostStep = (pc) => {
      if (pc === CODE) engine.memWrite(CODE + 7, Uint8Array.of(9));
    };
    engine.emuStart(CODE, CODE + 8);
    expect(engine.regRead(X86_REG.RAX)).toBe(10);
  });

  it('records only executed instructions when invalidation exits a block early', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(bytes('c7 06 2a 00 00 00 b8 01 00 00 00 83 c0 02')));
    engine.memWrite(DATA, Uint8Array.of(0x90));
    engine.regWrite(X86_REG.RSI, DATA);
    const first = engine.jit!.get(CODE, CODE + 14)!;
    first.next0 = engine.jit!.get(CODE + 6, CODE + 14);
    engine.jit!.get(DATA, DATA + 1);
    engine.jit!.executionLog = [];
    engine.emuStart(CODE, CODE + 14);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    expect(engine.jit!.executionLog.map(({ block, count }) => [block.start, count])).toEqual([
      [CODE, 1],
      [CODE + 6, 2],
    ]);
  });
});

describe('Shared memory spans and regions', () => {
  // mov ecx,256; xor eax,eax; L: mov edx,[rsi]; add eax,edx; mov [rdi],eax; push rax; pop rax; sub ecx,1; jnz L
  const LOOP = bytes('b9 00 01 00 00 31 c0 8b 16 01 d0 89 07 50 58 83 e9 01 75 f3');
  const loopEngine = (jit: boolean, regionHits = 8): TsX86Engine => {
    const engine = new TsX86Engine({ jit });
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    engine.memMap(STACK, 0x1000);
    engine.memWrite(CODE, Uint8Array.from(LOOP));
    engine.memWrite(DATA, Uint8Array.of(3));
    engine.regWrite(X86_REG.RSI, DATA);
    engine.regWrite(X86_REG.RDI, DATA + 0x100);
    engine.regWrite(X86_REG.RSP, STACK + 0x800);
    if (engine.jit) engine.jit.regionHits = regionHits;
    return engine;
  };
  const state = (engine: TsX86Engine) => ({
    rax: engine.regRead(X86_REG.RAX),
    rcx: engine.regRead(X86_REG.RCX),
    rsp: engine.regRead(X86_REG.RSP),
    rip: engine.regRead(X86_REG.RIP),
    sum: new DataView(engine.memRead(DATA + 0x100, 4).buffer).getUint32(0, true),
    count: engine.instructionCount,
  });

  it('checks one span per base register and reports its fault at the first use', () => {
    const engine = new TsX86Engine({ jit: true });
    engine.memMap(CODE, 0x1000);
    engine.memMap(DATA, 0x1000);
    // mov eax,[rsi]; mov ecx,[rsi+0x2000]: the second access is unmapped.
    engine.memWrite(CODE, Uint8Array.from(bytes('8b 06 8b 8e 00 20 00 00')));
    engine.memWrite(DATA, Uint8Array.of(7));
    engine.regWrite(X86_REG.RSI, DATA);
    expect(() => engine.emuStart(CODE, CODE + 8, 0, 1000)).toThrow('unmapped access');
    expect(engine.regRead(X86_REG.RIP)).toBe(CODE);
    expect(engine.regRead(X86_REG.RAX)).toBe(0);
    expect(engine.instructionCount).toBe(1);
  });

  it('merges touching mappings so one span can cover both', () => {
    for (const jit of [false, true]) {
      const engine = new TsX86Engine({ jit });
      engine.memMap(CODE, 0x1000);
      engine.memMap(DATA, 0x1000);
      engine.memMap(DATA + 0x1000, 0x1000);
      engine.memWrite(DATA + 0xffc, Uint8Array.of(1, 2, 3, 4, 0, 0, 0, 0));
      engine.memWrite(CODE, Uint8Array.from(bytes('48 8b 06 48 89 46 08')));
      engine.regWrite(X86_REG.RSI, DATA + 0xffc);
      engine.emuStart(CODE, CODE + 7, 0, 1000);
      expect(engine.regRead(X86_REG.RAX)).toBe(0x04030201);
      expect([...engine.memRead(DATA + 0x1004, 8)]).toEqual([1, 2, 3, 4, 0, 0, 0, 0]);
    }
  });

  it('compiles a hot loop into a region that matches the interpreter', () => {
    const reference = loopEngine(false);
    reference.emuStart(CODE, CODE + 20);
    const engine = loopEngine(true);
    engine.emuStart(CODE, CODE + 20);
    expect(state(engine)).toEqual(state(reference));
    expect(state(engine).sum).toBe(768);
    expect(engine.jit!.regionsBuilt).toBeGreaterThanOrEqual(1);
    expect(engine.jit!.regionInstructions).toBeGreaterThan(0);
  });

  it('keeps regions out of instruction-limited runs', () => {
    const reference = loopEngine(false);
    reference.emuStart(CODE, CODE + 20, 0, 1000);
    const engine = loopEngine(true);
    engine.emuStart(CODE, CODE + 20, 0, 1000);
    expect(state(engine)).toEqual(state(reference));
    expect(engine.instructionCount).toBe(1000);
    expect(engine.jit!.regionsBuilt).toBe(0);
  });

  it('logs executed members like the block path for differential validation', () => {
    const blocks = loopEngine(true, Infinity);
    blocks.jit!.executionLog = [];
    blocks.emuStart(CODE, CODE + 20);
    const regions = loopEngine(true);
    regions.jit!.executionLog = [];
    regions.emuStart(CODE, CODE + 20);
    expect(regions.jit!.regionsBuilt).toBeGreaterThanOrEqual(1);
    const trace = (log: { block: { start: number }; count: number }[]) => log.map((e) => [e.block.start, e.count]);
    expect(trace(regions.jit!.executionLog)).toEqual(trace(blocks.jit!.executionLog));
    expect(state(regions)).toEqual(state(blocks));
  });

  it('does not run a region when the stop address lies inside a member', () => {
    const engine = loopEngine(true);
    engine.emuStart(CODE, CODE + 20);
    expect(engine.jit!.regionsBuilt).toBeGreaterThanOrEqual(1);
    const before = engine.instructionCount;
    engine.regWrite(X86_REG.RSP, STACK + 0x800);
    engine.emuStart(CODE, CODE + 15);
    expect(engine.regRead(X86_REG.RIP)).toBe(CODE + 15);
    expect(engine.instructionCount - before).toBe(7);
  });

  it('leaves a region whose member writes into another compiled code page', () => {
    // mov ecx,64; L: mov byte [rip+0xff5],2 (the immediate of the block at CODE+0x1000); sub ecx,1; jnz L
    const program = bytes('b9 40 00 00 00 c6 05 f5 0f 00 00 02 83 e9 01 75 f4');
    const run = (jit: boolean) => {
      const engine = new TsX86Engine({ jit });
      engine.memMap(CODE, 0x2000);
      engine.memWrite(CODE, Uint8Array.from(program));
      // A compiled block in the second page: mov eax,1 becomes mov eax,2 once the loop writes.
      engine.memWrite(CODE + 0x1000, Uint8Array.from(bytes('b8 01 00 00 00 90')));
      engine.emuStart(CODE + 0x1000, CODE + 0x1006, 0, 1000);
      if (engine.jit) engine.jit.regionHits = 8;
      engine.emuStart(CODE, CODE + 17);
      engine.emuStart(CODE + 0x1000, CODE + 0x1006, 0, 1000);
      return [
        engine.regRead(X86_REG.RCX),
        engine.regRead(X86_REG.RAX),
        engine.instructionCount,
        engine.jit?.invalidations,
      ];
    };
    const [rcx, rax, count] = run(false);
    expect([rcx, rax, count]).toEqual([0, 2, 197]);
    const jit = run(true);
    expect(jit.slice(0, 3)).toEqual([rcx, rax, count]);
    expect(jit[3]).toBeGreaterThan(0);
  });
});
