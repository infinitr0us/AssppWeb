// Optional external oracle for research tools; never loaded by production.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function openUnicornReference() {
  const dir = process.env.KBSYNC_UNICORN_DIR;
  if (!dir) {
    throw new Error(
      'KBSYNC_UNICORN_DIR is required: point it to the historical engine.ts and vendor/unicorn.{mjs,wasm}',
    );
  }
  const { UnicornEngine } = await import(pathToFileURL(resolve(dir, 'engine.ts')).href);
  if (typeof UnicornEngine?.open !== 'function') {
    throw new Error('KBSYNC_UNICORN_DIR must contain the historical UnicornEngine, not the production engine');
  }
  const wasmBinary = new Uint8Array(readFileSync(resolve(dir, 'vendor/unicorn.wasm'))).buffer;
  return UnicornEngine.open({ wasmBinary });
}
