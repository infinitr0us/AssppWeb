// Runs the TypeScript guest engine off the main thread.

import { generateKBSync } from './storeAgent';
import type { KBSyncAssets } from './types';

interface GenerateRequest {
  assets: { [K in keyof KBSyncAssets]: ArrayBuffer };
  hardwareID: ArrayBuffer;
  dsid: number;
}

self.onmessage = async (event: MessageEvent<GenerateRequest>) => {
  const request = event.data;
  try {
    const kbsync = await generateKBSync(
      {
        commerceKit: new Uint8Array(request.assets.commerceKit),
        commerceCore: new Uint8Array(request.assets.commerceCore),
        coreFP: new Uint8Array(request.assets.coreFP),
        coreFPICXS: new Uint8Array(request.assets.coreFPICXS),
        storeAgent: new Uint8Array(request.assets.storeAgent),
      },
      new Uint8Array(request.hardwareID),
      request.dsid,
    );
    const buffer = kbsync.slice().buffer;
    self.postMessage({ type: 'result', kbsync: buffer }, { transfer: [buffer] });
  } catch (error) {
    self.postMessage({ type: 'error', message: error instanceof Error ? error.message : String(error) });
  }
};
