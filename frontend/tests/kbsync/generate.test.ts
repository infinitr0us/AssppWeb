// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadKBSyncAssets } from '../../src/apple/kbsync/assets';
import { generateKBSync } from '../../src/apple/kbsync/generate';
import type { KBSyncAssets } from '../../src/apple/kbsync/types';

vi.mock('../../src/apple/kbsync/assets', () => ({ loadKBSyncAssets: vi.fn() }));

const assets: KBSyncAssets = {
  commerceKit: Uint8Array.of(1),
  commerceCore: Uint8Array.of(2),
  coreFP: Uint8Array.of(3),
  coreFPICXS: Uint8Array.of(4),
  storeAgent: Uint8Array.of(5),
};

let worker: {
  onmessage: ((event: { data: { type: string; kbsync?: ArrayBuffer; message?: string } }) => void) | null;
  onerror: ((event: { message: string }) => void) | null;
  postMessage: ReturnType<typeof vi.fn>;
  terminate: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  vi.mocked(loadKBSyncAssets).mockReset().mockResolvedValue(assets);
  worker = { onmessage: null, onerror: null, postMessage: vi.fn(), terminate: vi.fn() };
  vi.stubGlobal(
    'Worker',
    vi.fn(function () {
      return worker;
    }),
  );
  vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('kbsync worker generation', () => {
  it('sends only guest assets and account/device identifiers, then releases the worker', async () => {
    const progress = vi.fn();
    const result = generateKBSync('aabbccddeeff', 123, progress);
    await Promise.resolve();

    expect(loadKBSyncAssets).toHaveBeenCalledWith(progress);
    expect(fetch).not.toHaveBeenCalled();
    expect(worker.postMessage).toHaveBeenCalledExactlyOnceWith({
      assets: Object.fromEntries(Object.entries(assets).map(([name, data]) => [name, data.buffer])),
      hardwareID: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).buffer,
      dsid: 123,
    });
    const message = worker.postMessage.mock.calls[0][0];
    expect(message.assets.coreFP).not.toBe(assets.coreFP.buffer);
    worker.onmessage!({ data: { type: 'result', kbsync: Uint8Array.from([0, 4, 0, 3]).buffer } });

    await expect(result).resolves.toBe('AAQAAw==');
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it('rejects an invalid device identifier before loading assets or creating a worker', async () => {
    await expect(generateKBSync('invalid', 123)).rejects.toThrow('six-byte hexadecimal');
    expect(loadKBSyncAssets).not.toHaveBeenCalled();
    expect(Worker).not.toHaveBeenCalled();
  });

  it.each(['message', 'error'])('releases the worker after a %s failure', async (failure) => {
    const result = generateKBSync('aabbccddeeff', 123);
    await Promise.resolve();
    if (failure === 'message') worker.onmessage!({ data: { type: 'error', message: 'guest failed' } });
    else worker.onerror!({ message: 'guest failed' });

    await expect(result).rejects.toThrow('guest failed');
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it('terminates a worker that does not respond before the generation deadline', async () => {
    vi.useFakeTimers();
    const result = generateKBSync('aabbccddeeff', 123);
    const rejected = expect(result).rejects.toThrow('kbsync generation timed out');
    await vi.advanceTimersByTimeAsync(6 * 60 * 1000);
    await rejected;
    expect(worker.terminate).toHaveBeenCalledOnce();
  });
});
