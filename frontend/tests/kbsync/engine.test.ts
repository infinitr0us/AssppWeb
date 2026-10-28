// @vitest-environment node
import { expect, it } from 'vitest';
import { GuestEngine, X86_REG } from '../../src/apple/kbsync/engine';

it('opens the production engine with JIT enabled', async () => {
  const engine = await GuestEngine.open();
  try {
    expect(engine.jit).not.toBeNull();
    engine.memMap(0x1000, 0x1000);
    engine.memWrite(0x1000, Uint8Array.from([0xb8, 1, 0, 0, 0, 0x83, 0xc0, 2]));
    engine.emuStart(0x1000, 0x1008, 1_000_000, 1000);
    expect(engine.regRead(X86_REG.RAX)).toBe(3);
    expect(engine.jit!.compiledInstructions).toBe(2);
  } finally {
    engine.close();
  }
});
