# TypeScript kbsync runtime

The `ent/download` request needs a kbsync blob for the account DSID and device
identifier. This project currently generates it in the browser by running the
StoreAgent, CoreFP, CommerceKit and CommerceCore x86_64 images with the
TypeScript block JIT. `GuestEngine.open()` enables JIT by default. The worker
receives the five Apple assets, hardware ID and DSID; it no longer downloads or
receives a Unicorn WASM module.
The legacy download fallback does not cover every app that needs `ent/download`
([ipatool issue #577](https://github.com/majd/ipatool/issues/577)).
The five Apple images, loader, shims and digest-checked asset delivery remain
required; replacing the emulator does not replace Apple’s guest algorithm.

## What was checked

- [`fairplay-decrypt`](https://github.com/EthanArbuckle/fairplay-decrypt)
  decrypts an IPA after download using a 16-byte credential retrieved from a
  jailbroken device. Its `core.py` and `decrypt.py` do not generate the kbsync
  value sent to `ent/download`. The repository does not currently publish a
  license, so its code should not be copied into this project.
- [`ipatool`](https://github.com/majd/ipatool/blob/master/internal/sap/machine/kbsync.go),
  [`sapsigner`](https://github.com/t0rr3sp3dr0/sapsigner/blob/master/impl/emu/mescal/emulator/emulator_fairplaykbsyncdatawithdsid.go)
  and [`WaffleStore`](https://github.com/nxtcoreee3/WaffleStore/blob/master/MapleSyrup/NativeSAP/main.go)
  still call an emulated StoreAgent for kbsync.
- Native iTunes and jailbroken-device tools obtain a blob by calling Apple's
  native code. They do not provide a portable browser implementation.
- The existing direct TypeScript SAP signer in `../sap/` proves a separate
  Apple protocol can run without emulation, but it only implements SAP setup
  and request signing. It has no kbsync entry point or matching test vector.

## Historical Unicorn baseline

The five images extracted by `backend/scripts/extract-sap-assets.mts` pass the
pinned hashes in `backend/src/services/sapAssets.ts`. With a synthetic DSID of
`12345678901` and device ID `0a1b2c3d4e5f`, the original Unicorn version of
`frontend/tests/kbsync/kbsync-live.mjs` returned a 196-byte blob on this host in
about 28–30 seconds. The first four bytes are `00 04 00 03`. Two independent
runs with identical input differed at 191 of 196 byte positions; a fixed blob
is not a substitute for generation.
[`ipatool` issue #631](https://github.com/majd/ipatool/issues/631) also reports
long first-generation times on slower hardware.

Temporary code hooks around exported guest functions placed approximately
29 seconds in StoreAgent global initialization and under 0.1 seconds in the
final kbsync call. Within initialization, CoreFP `_X46O5IeS` took about
9 seconds, while roughly 18 seconds remained in the StoreAgent call chain
after it returned. The entry points include indirect calls and `rdtsc`, so the
work cannot be reduced to formatting the DSID and device ID. Holding the JS
random source and wall clock fixed still produced different blobs in separate
processes; guest `rdtsc` is one possible remaining source of variation.

Ghidra 12.2 on Apple Silicon needed its native decompiler built locally. A
synthetic run resolved the CoreFP wrappers to offsets `0xcbb3b0` (initial
`CoreFP.icxs` loading), `0x1735d0` (the roughly nine-second setup call), and
`0x66dbc0` (the final call, made once during initialization and once for
kbsync). The first function reads and checks the 0x507640-byte `CoreFP.icxs`
image. The final function reserves a 0x149e8-byte stack frame and uses
overlapping instruction streams; Ghidra reports an unrecoverable instruction
overlap when decompiling it. The Mach-O function-start table places its next
function 0x4db880 bytes (about 4.9 MiB) later. These are concrete obstacles
to translating only the exported entry points.

With the current guest call sequence, reusing one initialized StoreAgent
context for a second kbsync call returned status `-42032` and no output, even
for the same DSID. A cache of the initialized context is therefore not a
validated way to avoid the setup cost. This experiment used synthetic input
and does not establish Apple's acceptance rules.

This is a synthetic offline check, not proof that the resulting blob is
accepted by Apple's live `ent/download` service. No real account was used.

## TypeScript interpreter checkpoint

`tsx86.ts` now replays the complete original final-call capture:
5,061,098 instruction addresses, 158,839 block register records, the 196-byte
output, post-dispose non-stack memory, and shim state all match Unicorn.
The block register recording uses Unicorn's f64 API; instruction regression
tests instead compare full register bytes stored to memory.

The interpreter preserves arbitrary 64-bit intermediate values with BigInt,
including encoded pointers and LEA arithmetic. The full trace also contains
XORPS/MOVAPS; the earlier claim of no SSE was based on an incomplete capture.
Standalone TS initialization and generation now succeed with synthetic input:
the checked-in offline harness completes in about 419 seconds using the default
RDTSC counter, including initialization, generation and disposal. This was measured
alongside other diagnostics, not in isolation. Earlier diagnostic runs put roughly
1.8–2 seconds in the final call; initialization dominates the runtime.
The complete initialization, final call and disposal also pass a live lockstep
comparison: 1,141,584,001 instructions, exact 64-bit values for all 16 GPRs at block
entries, every memory write, all mapped memory at call returns (including stack
and shims), and the 196-byte output match. The harness explicitly zeroes Unicorn
maps to avoid dirty allocator memory and supplies the same shim/RDTSC inputs.
This exposed and fixed a CPUID leaf 1 placeholder near the end of initialization.

Performance work remains. This is an experimental interpreter, not a complete
x86 implementation; the x87 layer still has approximate semantics.
See `docs/kbsync-reverse-engineering.md` for the current measurements and limits.

From the repository root:

```bash
# Existing offline capture (REPLAY_DIR and KBSYNC_ASSET_DIR can override paths).
node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-replay.mjs

# Full initialization + final call using the TS engine, with a bounded guest timeout.
KBSYNC_ENGINE=ts KBSYNC_ASSET_DIR=/tmp/asspp-sap/sap-assets \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-live.mjs

# Full interpreter lockstep comparison, using an external reference engine.
KBSYNC_UNICORN_DIR=/tmp/asspp-unicorn-reference KBSYNC_ASSET_DIR=/tmp/asspp-sap/sap-assets \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-init-diff.mjs
```

The live harness defaults to the production JIT path. `KBSYNC_ENGINE=ts`
explicitly selects the diagnostic interpreter. Offline byte equivalence does not prove live
Apple acceptance for a newly initialized TS context.

## Block JIT

`TsX86Engine({ jit: true })` translates hot integer basic blocks to JavaScript.
It keeps exact 64-bit values in low/high dwords, uses per-site DataView caches,
keeps register temporaries local, and follows cached successors in batches of
at most 4096 instructions plus the last block. Cold paths execute three times
in the interpreter before compilation. Unsupported instructions, including
RDTSC and the existing x87/SSE helpers, still use the interpreter.

Guest/host code writes invalidate affected code pages; mapping and hook changes
clear compiled blocks and memory-site caches. Instruction observers retain the
unoptimized per-instruction path through compiled blocks. The optimized path
also has an independent full-initialization differential mode: it checks every
Unicorn instruction address/length, all 16 exact GPRs and written bytes at each
batch exit, and all mapped memory and output at guest-call returns. Batch checks
compare the final value of overlapping writes, not each intermediate store.
The original interpreter lockstep mode is unchanged. The optimized full run
passed 1,141,537,075 instruction comparisons and 4,634,853 batch-boundary checks,
including initialization, generation, disposal, stack/shim memory and output.

Five isolated Node processes on this host measured a median of 5.872 seconds
for initialization (5.844–6.001s) and 236.59ms for the subsequent generation call
(235.90–239.39ms). These timings include JIT compilation and complete guest calls;
assets are local, so download time is excluded. The requested 5-second / 50ms
targets remain unmet; dedicated browser performance measurements and live Apple acceptance are untested.
The production worker now uses this JIT. The five Apple assets remain required.

After removing the bundled emulator, all 562 frontend tests pass with
`KBSYNC_UNICORN_DIR` pointing to a nonexistent directory. Type checking and the
production build pass. The built module worker also completes in the desktop
app's browser with the real local Apple assets and synthetic account/device input,
returning 196 bytes with prefix `00 04 00 03`. This is a functional browser check,
not an isolated performance measurement or a live Apple acceptance test.
The external oracle also passes a fresh full run after removal: 1,141,552,400
instructions and 4,627,513 batch boundaries, including all mapped stack/shim
memory and the 196-byte output.

```bash
# Full synthetic initialization and generation, with separate guest timings.
KBSYNC_ENGINE=jit KBSYNC_ASSET_DIR=/tmp/asspp-sap/sap-assets \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-live.mjs

# Every captured instruction, block registers, output, memory and shim state.
KBSYNC_ENGINE=jit \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-replay.mjs

# Optimized execution: output, memory and shim checks, without instruction observation.
KBSYNC_ENGINE=jit REPLAY_BENCH=1 \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-replay.mjs

# Full initialization differential check of the optimized execution path.
KBSYNC_ENGINE=jit KBSYNC_UNICORN_DIR=/tmp/asspp-unicorn-reference \
  KBSYNC_ASSET_DIR=/tmp/asspp-sap/sap-assets \
  node --import ./backend/node_modules/tsx/dist/loader.mjs frontend/tests/kbsync/kbsync-init-diff.mjs
```

## Shared memory spans and hot-loop regions

Two further changes to the block JIT (2026-10-25):

- **Shared base-register spans.** Index-free operands such as `[rbp-0x2490]`
  no longer carry their own mapping check. Within a block, all such operands of
  one base register share a single check covering the whole span of their
  displacements, performed when the register is first used and repeated only
  after the register is written. Accesses become one bounds-checked `DataView`
  call on a cached view. A fault anywhere in the span is reported at that first
  use; `memMap` merges touching mappings so a contiguous mapped span always has
  one backing view. Indexed operands keep exact modulo-2^64 addressing and
  per-access checks: `movq (%rcx,%r15)` at CoreFP `+0xd1f3ee` relies on the wrap.
- **Regions.** A block executed 500,000 times is compiled together with its hot
  successors into one function (`for(;;){switch(pc){...}}`) that keeps guest
  registers in locals across block boundaries. Members are admitted best-first
  by execution count under a generated-source budget of 18,000 characters,
  because V8 stops using its top optimizing tier for larger functions and the
  slower tiers run such code at 100–150 M instructions/s. Indirect jumps resolve
  against the observed successors first and then a compare tree over all
  members. A region that keeps exiting to non-member blocks is rebuilt at most
  twice around its frequent exits; the exit statistics skip the periodic budget
  returns (every 8,192 instructions) so the dispatcher can still check the
  deadline. Regions are disabled for instruction-limited runs, honour `until`,
  and log executed members when `executionLog` is set so the differential
  harness still sees every executed block.
- The batch loop moved to `runBatch`, and the dispatcher links regions like
  blocks, so a region exit does not fall back to a map lookup.

Three isolated runs on this host measured initialization at 4,031–4,042 ms and
generation at 229–231 ms (the same session measured the previous code at
6,410–6,582 ms and 262–267 ms; the machine was slower than when the earlier
5.872 s figure was taken). About 21–25 regions handle 843 M of the 1.14 B
initialization instructions at 680 M instructions/s overall; the storeagent
state-machine loop runs at about 890 M/s as one region. Per-block compile time
is now dominated by V8 parsing and lazily compiling the generated functions on
first call, which the `compilationMs` counter does not include. Remaining time:
about 1.2 s in regions, 0.45 s generating block sources, roughly 1 s of V8
compilation and warm-up for 4,450 block functions, and the rest in blocks and
the dispatcher. The generation target of 50 ms is still unmet: that call
compiles about 560 new blocks and runs them cold.

The unit tests cover the shared-span fault position, merged mappings, a hot
loop compiled into a region against the interpreter, regions under an
instruction budget, member logging, `until` inside a member, and a region whose
member writes into another compiled code page. The full optimized-path
differential check (`KBSYNC_ENGINE=jit kbsync-init-diff.mjs`, against the
historical Unicorn engine) passed after these changes: initialization
1,136,460,421 instructions and the final call and disposal 1,141,519,289 in
total, 4,321,395 batch boundaries with all 16 exact GPRs and written bytes
checked, all mapped memory (stack and shim areas included) and the 196-byte
output equal at every call return, in 265 s. Replaying the harness's driving
pattern (execution log on, stop after every batch) without the reference shows
25 regions built, 1.66 M region runs covering 834 M instructions and 90 M
member log entries, so the comparison covered the region path, not only
blocks.

## Reference tests without a bundled emulator

Ordinary unit tests read `tests/kbsync/fixtures/x86-reference.json`, recorded
from the historical Unicorn build. Both the interpreter and JIT compare their
full register/memory results against those fixed expectations. Missing vectors
fail the test; they are never generated from the implementation under test.

Live differential/capture tools use an explicit external reference engine.
To recover the previous oracle from repository history, run from the root:

```bash
export KBSYNC_UNICORN_DIR=/tmp/asspp-unicorn-reference
mkdir -p "$KBSYNC_UNICORN_DIR/vendor"
git show 67338e316679572de7433573d86a0671c62b9fdd:frontend/src/apple/kbsync/engine.ts > "$KBSYNC_UNICORN_DIR/engine.ts"
for name in unicorn.mjs unicorn.wasm unicorn.d.mts; do
  git show "67338e316679572de7433573d86a0671c62b9fdd:frontend/src/apple/kbsync/vendor/$name" > "$KBSYNC_UNICORN_DIR/vendor/$name"
done

# Explicitly re-record instruction fixtures from that external oracle.
node frontend/tests/kbsync/record-x86-fixtures.mjs
```

The reference assets and build scripts are absent from the source tree and
production bundle. This external setup is only needed to record new vectors or
run a live oracle comparison; normal unit tests and production generation need
no Unicorn installation.

## Live-service acceptance criteria

A browser generator must produce a blob accepted by `ent/download` for the
same account and device, including an uncached first download and a retry after
cached-blob rejection. It must keep the account credentials and Apple TLS in
the browser. Initialization equivalence is covered by offline differential tests. Live
Apple acceptance and performance targets still require their separate checks.

For the selected TS interpreter route, keep `machImage.ts`, `shims.ts`, the
StoreAgent images and their asset delivery: they still execute Apple's guest
code. The Unicorn engine/vendor/build integration has been removed. Removing the images and loader would
require a separate, independently validated implementation of the algorithm.
