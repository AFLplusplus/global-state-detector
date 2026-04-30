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

Linux (ELF) and macOS (Mach-O) are supported. The two paths are selected at
compile time and share all of the snapshot/diff/reporting logic.

Linux:

- `dl_iterate_phdr` to walk loaded objects
- `dladdr` and a fallback `/proc/self/exe` `SHT_SYMTAB` parser for symbol
  resolution (the parser also picks up `STB_LOCAL` symbols that `dladdr`
  cannot see, e.g. Rust binary-crate statics)
- ELF program headers from `<elf.h>` / `<link.h>`
- Link the harness with `-ldl -Wl,--export-dynamic -Wl,-z,now` so symbol
  names in the main executable can be resolved and lazy PLT/GOT binding
  does not show up as first-iteration writable state.

macOS:

- `_dyld_image_count` / `_dyld_get_image_header` / `_dyld_get_image_name`
  to walk loaded Mach-O images
- `dladdr` for symbol resolution (already iterates the in-memory `nlist`
  table, including locals — no separate fallback needed)
- Mach-O headers from `<mach-o/dyld.h>` / `<mach-o/loader.h>` /
  `<mach-o/getsect.h>`
- No extra link flags required. `dlopen`/`dladdr` ship in `libSystem`, and
  modern Mach-O linkers bind eagerly by default (chained fixups), so the
  Linux `-z,now` / `--export-dynamic` equivalents are unnecessary.

Builds should use a clang-based fuzzer compiler (e.g. `afl-clang-fast` for
AFL++, `clang` for libFuzzer).

### AddressSanitizer Is Broken On Recent macOS

On recent Darwin, `-fsanitize=address` does not work: any harness — even
hello-world — wedges at process init and spins at 100% CPU before `main`
runs. This has been observed with both Apple Silicon Apple Clang
(clang-2100.x) and Homebrew LLVM 21 on macOS 15+. The issue is in the
ASan runtime / loader interaction, not in this detector; the detector
itself works fine on macOS without ASan.

The provided Makefile therefore drops `address` from the example's
sanitizer set on Darwin, building with `-fsanitize=fuzzer,undefined`
instead of the full Linux `-fsanitize=fuzzer,address,undefined`. To
exercise ASan integration on macOS you'll need to find a working
clang/runtime combination and override `FUZZER_CFLAGS` /
`FUZZER_LDFLAGS` by hand.

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
still report expected state. On macOS the entire dyld shared cache and
`/System` frameworks tree are skipped by path prefix in addition to the
allocator basenames.

Only writable ELF segments are covered. If a target stores persistent state on
the heap or in custom mappings, this detector will not see it without additional
`/proc/self/maps` support.

The detector is not thread-safe. Use it from a single-threaded harness or add
external synchronization around initialization and checks.

## License

`global-state-detector` is distributed under the GNU Affero General Public
License version 3 or later. See `LICENSE` for the full license text.
