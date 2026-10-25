// @vitest-environment node
import { afterEach, expect, it, vi } from 'vitest';
import { openUnicornReference } from './unicorn-reference.mjs';

afterEach(() => vi.unstubAllEnvs());

it('requires an explicitly configured external oracle instead of using the production engine', async () => {
  vi.stubEnv('KBSYNC_UNICORN_DIR', undefined);
  await expect(openUnicornReference()).rejects.toThrow('KBSYNC_UNICORN_DIR is required');
});
