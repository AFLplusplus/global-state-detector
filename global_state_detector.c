/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * global_state_detector.c - detect persistent writable state between fuzzer
 * iterations
 * Copyright (C) 2026 Marc "vanHauser" Heuse <vh@thc.org>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Walks all writable PT_LOAD segments (Linux ELF, via dl_iterate_phdr) or
 * writable LC_SEGMENT segments (macOS Mach-O, via the dyld image APIs) of
 * the main binary and every loaded shared object, snapshots them, and
 * diffs on demand. Intended to be rebaselined immediately before target
 * execution and checked immediately after it to find globals that carry
 * state across invocations.
 *
 * Build:
 *   cc -O2 -g -c global_state_detector.c
 *
 *   Link your harness on Linux with -ldl, -Wl,--export-dynamic, and
 *   -Wl,-z,now so dladdr() can resolve symbols in the main binary and
 *   lazy binding does not look like target state.
 *   On macOS link with -Wl,-bind_at_load (the lazy-binding equivalent);
 *   dlopen/dladdr ship in libSystem so no explicit -ldl is required.
 *
 * Caveats:
 *   - sanitizer coverage counters are ignored when their __sancov_cntrs
 *     range is detected (linker-provided weak symbols on Linux,
 *     getsectiondata() on Mach-O for the main image).
 *   - libc / libSystem itself has writable state (stdio buffers, errno TLS
 *     fallback, locale, malloc arenas if they live in .bss). Expect noise
 *     there; the detector skips well-known system images by path/name.
 *   - Heap / mmap-backed state is NOT covered (only .data/.bss-equivalent
 *     of loaded objects). For that, parse /proc/self/maps (Linux) or
 *     vm_region_recurse (macOS) additionally.
 *   - Not thread-safe. Call from a single thread.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#  include <elf.h>
#  include <link.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <mach-o/getsect.h>
#  include <mach-o/loader.h>
#  include <mach/vm_prot.h>
#else
#  error "global-state-detector currently supports Linux and macOS only"
#endif

#include "global_state_detector.h"

#if defined(__linux__)
#  if defined(__LP64__) || defined(_LP64)
#    define PROBE_ST_TYPE(x) ELF64_ST_TYPE(x)
#  else
#    define PROBE_ST_TYPE(x) ELF32_ST_TYPE(x)
#  endif
#elif defined(__APPLE__)
#  if defined(__LP64__)
typedef struct mach_header_64 macho_header_t;
typedef struct segment_command_64 macho_segment_t;
#    define MACHO_LC_SEGMENT LC_SEGMENT_64
#  else
typedef struct mach_header macho_header_t;
typedef struct segment_command macho_segment_t;
#    define MACHO_LC_SEGMENT LC_SEGMENT
#  endif
#endif

#define PROBE_PAGE_SIZE 4096
#define PROBE_MAX_REGIONS 512
#define PROBE_MAX_REPORTS 32                              /* per check call */

/* AddressSanitizer instruments globals with red zones and intercepts memcpy.
 * Walking entire writable PT_LOAD segments unavoidably crosses those red
 * zones, which would trip global-buffer-overflow on every iteration. The
 * detector reads raw bytes only to hash and snapshot them, so we exempt the
 * accessor functions and use an open-coded copy that the ASAN runtime does
 * not intercept. */
#if defined(__has_attribute)
#  if __has_attribute(no_sanitize_address)
#    define PROBE_NO_ASAN __attribute__((no_sanitize_address))
#  endif
#endif
#ifndef PROBE_NO_ASAN
#  define PROBE_NO_ASAN
#endif

static PROBE_NO_ASAN void probe_bytecopy(uint8_t *dst, const uint8_t *src,
                                         size_t n) {

  for (size_t i = 0; i < n; i++)
    dst[i] = src[i];

}

typedef struct {

  const char *module;
  uint8_t *start;
  size_t len;
  size_t npages;
  uint32_t *page_hash;
  uint8_t *snapshot;

} region_t;

#if defined(__linux__)
extern uint8_t __start___sancov_cntrs[] __attribute__((weak));
extern uint8_t __stop___sancov_cntrs[] __attribute__((weak));
#endif

static region_t g_regions[PROBE_MAX_REGIONS];
static size_t g_nregions = 0;
static size_t g_nskipped = 0;
static int g_initialized = 0;

/* SanitizerCoverage 8-bit-counter range to ignore during snapshot/diff.
 * Populated from linker-provided weak symbols on Linux and from
 * getsectiondata(__DATA, __sancov_cntrs) on macOS. Zero start/end means
 * "no range known" and disables the filter. */
static uintptr_t g_sancov_start = 0;
static uintptr_t g_sancov_end = 0;

/* Static symbol table for the main binary, loaded from the on-disk image
 * at init() time on Linux only. Linux dladdr() consults the dynamic
 * symtab, which omits STB_LOCAL symbols even with -rdynamic, so Rust
 * statics and other internal-linkage globals would resolve as "?+0x..."
 * without this fallback. macOS dladdr() already iterates the in-memory
 * nlist table (including local symbols), so the fallback is unused
 * there. */
typedef struct {

  uintptr_t addr;
  size_t size;
  const char *name;

} sym_entry_t;

static sym_entry_t *g_main_syms = NULL;
static size_t g_main_nsyms = 0;
static char *g_main_strtab = NULL;
static uintptr_t g_main_base = 0;

static int ignored_addr(uintptr_t addr) {

  if (g_sancov_end > g_sancov_start && addr >= g_sancov_start &&
      addr < g_sancov_end)
    return 1;

  return 0;

}

#if defined(__linux__)

/* Modules whose writable state we consider uninteresting noise.
 * Matched against the basename of dlpi_name with prefix semantics.
 * Empty dlpi_name (the main binary) is never skipped. */
static const char *const g_skip_prefixes[] = {

    "libc.so",                                   /* glibc merged            */
    "libc-",                                    /* older glibc: libc-2.x.so */
    "ld-linux",                                  /* dynamic linker          */
    "ld-",                                       /* generic ld-*.so         */
    "libpthread.so",                             /* legacy libpthread split */
    "libpthread-",
    "libstdc++.so",                              /* GNU C++ stdlib          */
    "libstdc++-",
    "linux-vdso.so",                             /* vdso                    */
    "libjemalloc",                               /* jemalloc allocator      */
    "libmimalloc",                               /* mimalloc allocator      */
    "libtcmalloc",                       /* gperftools tcmalloc (+_minimal) */
    "libhoard",                                  /* Hoard allocator         */
    "libsnmalloc",                               /* snmalloc allocator      */
    "librpmalloc",                               /* rpmalloc allocator      */
    "libscudo",                                  /* Scudo hardened malloc   */
    NULL};

static int should_skip_module(const char *name) {

  if (!name || !name[0])
    return 0;                                                /* main binary */
  const char *base = strrchr(name, '/');
  base = base ? base + 1 : name;
  for (int i = 0; g_skip_prefixes[i]; i++) {

    size_t n = strlen(g_skip_prefixes[i]);
    if (strncmp(base, g_skip_prefixes[i], n) == 0)
      return 1;

  }

  return 0;

}

#elif defined(__APPLE__)

/* User-installed allocator dylib basenames, mirrored from the Linux skip
 * list. The dyld shared cache (libsystem_*, libdyld, libobjc, libc++,
 * Frameworks) is filtered separately by path prefix below. */
static const char *const g_macos_skip_basenames[] = {

    "libjemalloc",
    "libmimalloc",
    "libtcmalloc",
    "libhoard",
    "libsnmalloc",
    "librpmalloc",
    "libscudo",
    NULL};

static int should_skip_module(const char *path) {

  if (!path)
    return 0;
  /* Everything in /usr/lib and /System is dyld-shared-cache / system
   * frameworks - the macOS analogue of the libc/ld-linux noise we filter
   * on Linux. */
  if (strncmp(path, "/usr/lib/", 9) == 0)
    return 1;
  if (strncmp(path, "/System/", 8) == 0)
    return 1;

  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
  for (int i = 0; g_macos_skip_basenames[i]; i++) {

    size_t n = strlen(g_macos_skip_basenames[i]);
    if (strncmp(base, g_macos_skip_basenames[i], n) == 0)
      return 1;

  }

  return 0;

}

#endif

/* FNV-1a, fast enough per page; swap for CRC32 intrinsic if you care. */
static PROBE_NO_ASAN uint32_t hash_region_page(const region_t *r, size_t off,
                                               size_t n) {

  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) {

    uintptr_t addr = (uintptr_t)(r->start + off + i);
    uint8_t b = ignored_addr(addr) ? r->snapshot[off + i] : r->start[off + i];
    h ^= b;
    h *= 16777619u;

  }

  return h;

}

static int add_region(const char *module, uint8_t *start, size_t len) {

  if (g_nregions >= PROBE_MAX_REGIONS) {

    fprintf(stderr, "[global-state-detector] PROBE_MAX_REGIONS exceeded\n");
    return -1;

  }

  region_t *r = &g_regions[g_nregions++];
  r->module = module;
  r->start = start;
  r->len = len;
  r->npages = (r->len + PROBE_PAGE_SIZE - 1) / PROBE_PAGE_SIZE;
  r->page_hash = (uint32_t *)calloc(r->npages, sizeof(uint32_t));
  r->snapshot = (uint8_t *)malloc(r->npages * PROBE_PAGE_SIZE);
  if (!r->page_hash || !r->snapshot) {

    fprintf(stderr, "[global-state-detector] allocation failed\n");
    abort();

  }

  return 0;

}

#if defined(__linux__)

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {

  (void)sz;
  (void)data;

  /* Record the main binary's load address so we can offset static-symtab
   * st_value entries for PIE binaries. The main binary always reports an
   * empty dlpi_name on glibc. */
  if (!info->dlpi_name || !info->dlpi_name[0])
    g_main_base = (uintptr_t)info->dlpi_addr;

  if (should_skip_module(info->dlpi_name)) {

    g_nskipped++;
    return 0;

  }

  for (int i = 0; i < info->dlpi_phnum; i++) {

    const ElfW(Phdr) *p = &info->dlpi_phdr[i];
    if (p->p_type != PT_LOAD)
      continue;
    if (!(p->p_flags & PF_W))
      continue;
    if (p->p_flags & PF_X)
      continue;                                       /* W+X: skip, unusual */
    if (p->p_memsz == 0)
      continue;

    const char *module =
        (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "[main]";
    if (add_region(module, (uint8_t *)(info->dlpi_addr + p->p_vaddr),
                   (size_t)p->p_memsz) != 0)
      return 1;

  }

  return 0;

}

static void discover_regions(void) {

  dl_iterate_phdr(phdr_cb, NULL);

}

static void resolve_sancov_range(void) {

  if (__start___sancov_cntrs && __stop___sancov_cntrs) {

    g_sancov_start = (uintptr_t)__start___sancov_cntrs;
    g_sancov_end = (uintptr_t)__stop___sancov_cntrs;

  }

}

#elif defined(__APPLE__)

static void discover_regions(void) {

  uint32_t n = _dyld_image_count();
  for (uint32_t i = 0; i < n; i++) {

    const char *path = _dyld_get_image_name(i);
    const macho_header_t *mh =
        (const macho_header_t *)_dyld_get_image_header(i);
    if (!mh)
      continue;
    intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    int is_main = (i == 0);

    if (is_main) {

      g_main_base = (uintptr_t)slide;

    } else if (should_skip_module(path)) {

      g_nskipped++;
      continue;

    }

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t j = 0; j < mh->ncmds; j++) {

      if (lc->cmd == MACHO_LC_SEGMENT) {

        const macho_segment_t *seg = (const macho_segment_t *)lc;
        /* Match the Linux PT_LOAD filter: writable, non-executable,
         * non-empty. __PAGEZERO has initprot=0 so it is filtered here;
         * __LINKEDIT is read-only so it is too; __TEXT is executable.
         * That leaves __DATA (the .data/.bss-equivalent we want) and
         * any other writable user segments. */
        if ((seg->initprot & VM_PROT_WRITE) &&
            !(seg->initprot & VM_PROT_EXECUTE) && seg->vmsize > 0) {

          uint8_t *start =
              (uint8_t *)((uintptr_t)seg->vmaddr + (uintptr_t)slide);
          const char *module = is_main ? "[main]" : (path ? path : "[?]");
          if (add_region(module, start, (size_t)seg->vmsize) != 0)
            return;

        }

      }

      lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);

    }

  }

}

static void resolve_sancov_range(void) {

  /* SanitizerCoverage emits inline-8bit-counters into __DATA,__sancov_cntrs
   * on Mach-O. getsectiondata() returns a runtime-relocated pointer with
   * slide already applied. Only the main image is consulted, mirroring
   * the linker-provided weak-symbol scope on Linux. */
  const macho_header_t *mh = (const macho_header_t *)_dyld_get_image_header(0);
  if (!mh)
    return;
  unsigned long sz = 0;
  uint8_t *p =
      getsectiondata((macho_header_t *)mh, "__DATA", "__sancov_cntrs", &sz);
  if (p && sz) {

    g_sancov_start = (uintptr_t)p;
    g_sancov_end = (uintptr_t)p + sz;

  }

}

#endif

static PROBE_NO_ASAN void snapshot_region(region_t *r) {

  for (size_t i = 0; i < r->npages; i++) {

    size_t off = i * PROBE_PAGE_SIZE;
    size_t n =
        (off + PROBE_PAGE_SIZE > r->len) ? (r->len - off) : PROBE_PAGE_SIZE;
    probe_bytecopy(r->snapshot + off, r->start + off, n);
    r->page_hash[i] = hash_region_page(r, off, n);

  }

}

#if defined(__linux__)

static int sym_cmp(const void *a, const void *b) {

  const sym_entry_t *sa = (const sym_entry_t *)a;
  const sym_entry_t *sb = (const sym_entry_t *)b;
  if (sa->addr < sb->addr)
    return -1;
  if (sa->addr > sb->addr)
    return 1;
  return 0;

}

static void load_main_symtab(void) {

  int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return;

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {

    close(fd);
    return;

  }

  size_t fsz = (size_t)st.st_size;
  void *map = mmap(NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED)
    return;

  const uint8_t *base = (const uint8_t *)map;
  const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)base;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
    goto out;
  if (eh->e_shoff == 0 || eh->e_shentsize != sizeof(ElfW(Shdr)))
    goto out;
  if ((size_t)eh->e_shoff + (size_t)eh->e_shnum * sizeof(ElfW(Shdr)) > fsz)
    goto out;

  const ElfW(Shdr) *sh = (const ElfW(Shdr) *)(base + eh->e_shoff);
  const ElfW(Shdr) *symsh = NULL, *strsh = NULL;
  for (uint16_t i = 0; i < eh->e_shnum; i++) {

    if (sh[i].sh_type == SHT_SYMTAB) {

      symsh = &sh[i];
      if (sh[i].sh_link < eh->e_shnum)
        strsh = &sh[sh[i].sh_link];
      break;

    }

  }
  if (!symsh || !strsh || symsh->sh_entsize == 0)
    goto out;
  if ((size_t)symsh->sh_offset + (size_t)symsh->sh_size > fsz)
    goto out;
  if ((size_t)strsh->sh_offset + (size_t)strsh->sh_size > fsz)
    goto out;

  size_t nent = symsh->sh_size / symsh->sh_entsize;
  const ElfW(Sym) *syms = (const ElfW(Sym) *)(base + symsh->sh_offset);
  const char *strtab = (const char *)(base + strsh->sh_offset);
  size_t strtab_sz = (size_t)strsh->sh_size;

  /* Copy the strtab so it survives munmap. */
  g_main_strtab = (char *)malloc(strtab_sz);
  if (!g_main_strtab)
    goto out;
  memcpy(g_main_strtab, strtab, strtab_sz);

  /* Two-pass: count, allocate, populate. */
  size_t count = 0;
  for (size_t i = 0; i < nent; i++) {

    unsigned char t = PROBE_ST_TYPE(syms[i].st_info);
    if (t != STT_OBJECT && t != STT_FUNC)
      continue;
    if (syms[i].st_shndx == SHN_UNDEF || syms[i].st_shndx == SHN_ABS)
      continue;
    if (syms[i].st_size == 0)
      continue;
    if (syms[i].st_name == 0 || syms[i].st_name >= strtab_sz)
      continue;
    count++;

  }

  if (count == 0)
    goto out;

  g_main_syms = (sym_entry_t *)malloc(count * sizeof(sym_entry_t));
  if (!g_main_syms) {

    free(g_main_strtab);
    g_main_strtab = NULL;
    goto out;

  }

  size_t k = 0;
  for (size_t i = 0; i < nent && k < count; i++) {

    unsigned char t = PROBE_ST_TYPE(syms[i].st_info);
    if (t != STT_OBJECT && t != STT_FUNC)
      continue;
    if (syms[i].st_shndx == SHN_UNDEF || syms[i].st_shndx == SHN_ABS)
      continue;
    if (syms[i].st_size == 0)
      continue;
    if (syms[i].st_name == 0 || syms[i].st_name >= strtab_sz)
      continue;
    g_main_syms[k].addr = g_main_base + (uintptr_t)syms[i].st_value;
    g_main_syms[k].size = (size_t)syms[i].st_size;
    g_main_syms[k].name = g_main_strtab + syms[i].st_name;
    k++;

  }
  g_main_nsyms = k;

  qsort(g_main_syms, g_main_nsyms, sizeof(sym_entry_t), sym_cmp);

out:
  munmap(map, fsz);

}

static int lookup_main_symbol(uintptr_t addr, const char **name,
                              ptrdiff_t *off) {

  if (g_main_nsyms == 0)
    return 0;

  /* Largest entry with addr <= query. */
  size_t lo = 0, hi = g_main_nsyms;
  while (lo < hi) {

    size_t mid = lo + (hi - lo) / 2;
    if (g_main_syms[mid].addr <= addr)
      lo = mid + 1;
    else
      hi = mid;

  }
  if (lo == 0)
    return 0;
  const sym_entry_t *e = &g_main_syms[lo - 1];
  if (addr < e->addr || addr >= e->addr + e->size)
    return 0;
  *name = e->name;
  *off = (ptrdiff_t)(addr - e->addr);
  return 1;

}

#endif  /* __linux__ */

void global_state_detector_init(void) {

  if (g_initialized)
    return;
  resolve_sancov_range();
  discover_regions();
#if defined(__linux__)
  load_main_symtab();
#endif
  g_initialized = 1;
  for (size_t i = 0; i < g_nregions; i++)
    snapshot_region(&g_regions[i]);

  size_t total = 0;
  for (size_t i = 0; i < g_nregions; i++)
    total += g_regions[i].len;
  fprintf(stderr,
          "[global-state-detector] init: %zu regions, %zu bytes, %zu modules skipped, %zu main symbols\n",
          g_nregions, total, g_nskipped, g_main_nsyms);

}

static void resolve_sym(uintptr_t addr, const char **name, ptrdiff_t *off) {

#if defined(__linux__)
  /* Prefer the static symtab for the main binary - it includes STB_LOCAL
   * symbols (Rust statics, internal C/C++ globals) that Linux dladdr
   * cannot see. Fall through to dladdr for shared libraries. macOS
   * dladdr already covers locals so this fallback is Linux-only. */
  if (lookup_main_symbol(addr, name, off))
    return;
#endif

  Dl_info di;
  if (dladdr((void *)addr, &di) && di.dli_sname) {

    *name = di.dli_sname;
    *off = (ptrdiff_t)(addr - (uintptr_t)di.dli_saddr);

  } else {

    *name = "?";
    *off = 0;

  }

}

static PROBE_NO_ASAN void report_page_diff(region_t *r, size_t page,
                                           int *reports_left) {

  size_t off = page * PROBE_PAGE_SIZE;
  size_t n =
      (off + PROBE_PAGE_SIZE > r->len) ? (r->len - off) : PROBE_PAGE_SIZE;
  const uint8_t *now = r->start + off;
  const uint8_t *then = r->snapshot + off;

  size_t i = 0;
  while (i < n && *reports_left > 0) {

    if (ignored_addr((uintptr_t)(now + i)) || now[i] == then[i]) {

      i++;
      continue;

    }

    size_t run_start = i;
    while (i < n && !ignored_addr((uintptr_t)(now + i)) && now[i] != then[i])
      i++;
    size_t run_len = i - run_start;

    uintptr_t addr = (uintptr_t)(r->start + off + run_start);
    const char *sym;
    ptrdiff_t sym_off;
    resolve_sym(addr, &sym, &sym_off);

    fprintf(stderr, "[global-state-detector] CHANGE %p len=%zu  %s+0x%zx  (%s)\n",
            (void *)addr, run_len, sym, (size_t)sym_off, r->module);

    /* Dump up to 16 bytes of before/after for the run. */
    size_t dump = run_len < 16 ? run_len : 16;
    fprintf(stderr, "               was:");
    for (size_t k = 0; k < dump; k++)
      fprintf(stderr, " %02x", then[run_start + k]);
    fprintf(stderr, "\n               now:");
    for (size_t k = 0; k < dump; k++)
      fprintf(stderr, " %02x", now[run_start + k]);
    fprintf(stderr, "\n");

    (*reports_left)--;

  }

}

PROBE_NO_ASAN int global_state_detector_check(int rebaseline) {

  if (!g_initialized) {

    global_state_detector_init();
    return 0;

  }

  int changes = 0;
  int reports_left = PROBE_MAX_REPORTS;

  for (size_t i = 0; i < g_nregions; i++) {

    region_t *r = &g_regions[i];
    for (size_t p = 0; p < r->npages; p++) {

      size_t off = p * PROBE_PAGE_SIZE;
      size_t n =
          (off + PROBE_PAGE_SIZE > r->len) ? (r->len - off) : PROBE_PAGE_SIZE;
      uint32_t h = hash_region_page(r, off, n);
      if (h == r->page_hash[p])
        continue;

      changes++;
      if (reports_left > 0)
        report_page_diff(r, p, &reports_left);

      if (rebaseline) {

        probe_bytecopy(r->snapshot + off, r->start + off, n);
        r->page_hash[p] = h;

      }

    }

  }

  return changes;

}

void global_state_detector_rebaseline(void) {

  if (!g_initialized) {

    global_state_detector_init();
    return;

  }

  for (size_t i = 0; i < g_nregions; i++)
    snapshot_region(&g_regions[i]);

}
