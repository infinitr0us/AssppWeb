// Runs kbsync generation in a Web Worker. Credentials never leave the
// browser: the worker only receives the device GUID bytes and the account DSID.

import { toBase64 } from '../sap/bytes';
import { loadKBSyncAssets } from './assets';

// Bounds asset loading plus the emulated StoreAgent calls.
const GENERATION_TIMEOUT_MS = 6 * 60 * 1000;

export function hardwareIDFromDeviceIdentifier(deviceIdentifier: string): Uint8Array {
  if (!/^[0-9a-fA-F]{12}$/.test(deviceIdentifier)) {
    throw new Error('kbsync requires a six-byte hexadecimal device identifier');
  }
  return Uint8Array.from(deviceIdentifier.match(/../g)!, (byte) => parseInt(byte, 16));
}

/** Generates a base64 kbsync blob for this account and device. */
export async function generateKBSync(
  deviceIdentifier: string,
  dsid: number,
  onProgress?: (loadedBytes: number, totalBytes: number) => void,
): Promise<string> {
  const hardwareID = hardwareIDFromDeviceIdentifier(deviceIdentifier);
  const assets = await loadKBSyncAssets(onProgress);

  const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
  try {
    const kbsync = await new Promise<ArrayBuffer>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('kbsync generation timed out')), GENERATION_TIMEOUT_MS);
      worker.onmessage = (event: MessageEvent<{ type: string; kbsync?: ArrayBuffer; message?: string }>) => {
        clearTimeout(timer);
        if (event.data.type === 'result' && event.data.kbsync) {
          resolve(event.data.kbsync);
        } else {
          reject(new Error(event.data.message ?? 'kbsync generation failed'));
        }
      };
      worker.onerror = (event) => {
        clearTimeout(timer);
        reject(new Error(event.message || 'kbsync worker failed'));
      };
      worker.postMessage({
        assets: {
          commerceKit: assets.commerceKit.slice().buffer,
          commerceCore: assets.commerceCore.slice().buffer,
          coreFP: assets.coreFP.slice().buffer,
          coreFPICXS: assets.coreFPICXS.slice().buffer,
          storeAgent: assets.storeAgent.slice().buffer,
        },
        hardwareID: hardwareID.slice().buffer,
        dsid,
      });
    });
    return toBase64(new Uint8Array(kbsync));
  } finally {
    // The guest heap is large; release it as soon as generation finishes.
    worker.terminate();
  }
}
