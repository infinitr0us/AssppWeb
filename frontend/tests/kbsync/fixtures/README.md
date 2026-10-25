# x86 reference cases

`x86-reference.json` contains 366 programs recorded with the historical Unicorn
engine. Each key is the complete guest program as hexadecimal bytes, including
the register/flags capture footer. Each value is the full 256-byte result region
encoded as base64. Tests apply their original flags mask after decoding; other
bytes remain part of the comparison for both the interpreter and JIT.

The `oracle` fields pin the SHA-256 digests of the wrapper, WASM binary and JS
glue used for recording. Normal tests read this file and do not load an emulator
reference or require the external directory. Missing programs fail with an
instruction to record the new case; tests never derive expected results from TS.

To refresh after adding instruction cases, supply the historical external
oracle directory containing `engine.ts` and `vendor/unicorn.{mjs,wasm}`:

```bash
KBSYNC_UNICORN_DIR=/path/to/unicorn-reference \
  node frontend/tests/kbsync/record-x86-fixtures.mjs
```

The recorder executes the current tests against that oracle and both TS modes,
checks duplicate programs agree, and writes the fixture only after the complete
run succeeds. Review changed expectations before committing them. The external
oracle files are not part of the production build or required by normal CI.
