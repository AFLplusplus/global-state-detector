CC := clang
CFLAGS := -I. -g -O1

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  FUZZER_CFLAGS  := -fsanitize=fuzzer,address,undefined
  FUZZER_LDFLAGS := -fsanitize=fuzzer,address,undefined
  LDLIBS  := -ldl
  LDFLAGS := -Wl,--export-dynamic -Wl,-z,now
else ifeq ($(UNAME_S),Darwin)
  # dlopen/dladdr live in libSystem (no -ldl needed). Modern Mach-O linkers
  # bind eagerly by default (chained fixups), so no -z,now equivalent is
  # required - first-iteration GOT writes that the Linux build avoids via
  # -Wl,-z,now do not appear here.
  #
  # ASan is dropped on macOS: -fsanitize=address wedges the harness at
  # process init under both Apple Clang and current Homebrew LLVM on recent
  # Darwin, spinning at 100% CPU before main() ever runs. The detector
  # itself is unaffected; build with just fuzzer+ubsan here.
  FUZZER_CFLAGS  := -fsanitize=fuzzer,undefined
  FUZZER_LDFLAGS := -fsanitize=fuzzer,undefined
  LDLIBS  :=
  LDFLAGS :=
else
  FUZZER_CFLAGS  := -fsanitize=fuzzer,address,undefined
  FUZZER_LDFLAGS := -fsanitize=fuzzer,address,undefined
  LDLIBS  :=
  LDFLAGS :=
endif

all:	harness_example global_state_detector.o

global_state_detector.o:	global_state_detector.c global_state_detector.h
	$(CC) $(CFLAGS) -c global_state_detector.c

harness_example.o:	harness_example.c global_state_detector.h
	$(CC) $(FUZZER_CFLAGS) $(CFLAGS) -c harness_example.c

harness_example:	global_state_detector.o harness_example.o
	$(CC) $(FUZZER_LDFLAGS) $(CFLAGS) $(LDFLAGS) -o harness_example harness_example.o global_state_detector.o $(LDLIBS)

clean:
	rm -f harness_example global_state_detector.o harness_example.o
