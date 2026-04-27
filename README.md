# global-state-detector

`global-state-detector` is a small C helper for `LLVMFuzzerTestOneInput` and AFL
`__AFL_LOOP` persistent harnesses that report instability (a value that you can
see when using AFL++'s `afl-fuzz` or in LibAFL).

It discovers persistent writable global state between fuzzer iterations by
snapshotting writable ELF `PT_LOAD` segments after target initialization, then
compares later memory against that baseline so target globals that drift across
inputs are visible.

This is useful when a fuzz target is expected to be deterministic and
iteration-local, but hidden `.data` or `.bss` state makes later inputs depend on
earlier ones.

## What It Checks

- Writable non-executable `PT_LOAD` segments in the main binary.
- Writable non-executable `PT_LOAD` segments in loaded shared objects discovered
  through `dl_iterate_phdr`.
- Page-level changes using a fast hash, followed by byte-range reporting for
  changed pages.
- Clang sanitizer coverage counters are ignored when the `__sancov_cntrs` range
  is present, so normal libFuzzer coverage does not dominate reports.

The detector intentionally does not inspect heap objects, anonymous mappings,
thread-local storage, files, sockets, or other external process state.

## Platform Assumptions

The implementation targets Linux ELF processes and uses:

- `dl_iterate_phdr`
- `dladdr`
- ELF program headers from `<elf.h>` and `<link.h>`

Builds should use a clang based fuzzer compiler (e.g. `afl-clang-fast` for
AFL++, `clang` for libfuzzer, etc.).
Link with `-ldl -Wl,--export-dynamic -Wl,-z,now` for best results so symbol
names in the main executable can be resolved in reports and lazy PLT/GOT binding
does not show up as first-iteration writable state.

## Build

```sh
make
```

This builds:

- `global_state_detector.o`
- `harness_example`

## Harness Integration

Include the `global_state_detector.h` header and run any one-time target
initialization before taking the detector snapshot:

```c
#include "global_state_detector.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  /* target_init(); */

  return 0;
}
```

Take or refresh the snapshot immediately before target execution and check
immediately after it. This avoids reporting a fuzzer's own bookkeeping mutations
between callbacks while still reporting writable global state changed by the
target:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int detector_ready = 0;

  if (!detector_ready) {
    detector_ready = 1;
    global_state_detector_init();
  } else {
    global_state_detector_rebaseline();
  }

  target_process(data, size);

  global_state_detector_check(/*rebaseline=*/1);

  return 0;
}
```

Pass a non-zero `rebaseline` value to update the snapshot after reporting. Pass
`0` to keep comparing against the previous snapshot and report cumulative drift.

## Example

Build and run the included example:

```sh
make
./harness_example -runs=50
```

The example intentionally mutates `target_accumulator` in `target_process`, so
the detector should report changed writable state during fuzz iterations.

Example report shape:

```text
[global-state-detector] CHANGE 0x... len=...  symbol+0x...  ([main])
               was: ...
               now: ...
```

## Noise And Limitations

Some runtime libraries maintain writable process state. The detector skips
common libc, dynamic-linker, pthread, libstdc++, vDSO, and replacement malloc
implementations (jemalloc, mimalloc, tcmalloc, Hoard, snmalloc, rpmalloc,
Scudo) by basename prefix to reduce noise, but target-specific libraries may
still report expected state.

Only writable ELF segments are covered. If a target stores persistent state on
the heap or in custom mappings, this detector will not see it without additional
`/proc/self/maps` support.

The detector is not thread-safe. Use it from a single-threaded harness or add
external synchronization around initialization and checks.

## License

`global-state-detector` is distributed under the GNU Affero General Public
License version 3 or later. See `LICENSE` for the full license text.
