// Production x86_64 guest engine; keep construction separate from the loader
// so offline differential tools can substitute their reference engine.

import { TsX86Engine } from './tsx86';

export { X86_REG } from './tsx86';

export class GuestEngine extends TsX86Engine {
  constructor() {
    super({ jit: true });
  }

  static async open(): Promise<GuestEngine> {
    return new GuestEngine();
  }

  override hookDel(_handle?: number): void {
    super.hookDel();
  }
}
