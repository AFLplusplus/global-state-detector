CC := clang
CFLAGS := -I. -g -O1
FUZZER_CFLAGS := -fsanitize=fuzzer,address,undefined
FUZZER_LDFLAGS := -fsanitize=fuzzer,address,undefined
LDLIBS := -ldl
LDFLAGS := -Wl,--export-dynamic -Wl,-z,now

all:	harness_example global_state_detector.o

global_state_detector.o:	global_state_detector.c global_state_detector.h
	$(CC) $(CFLAGS) -c global_state_detector.c

harness_example.o:	harness_example.c global_state_detector.h
	$(CC) $(FUZZER_CFLAGS) $(CFLAGS) -c harness_example.c

harness_example:	global_state_detector.o harness_example.o
	$(CC) $(FUZZER_LDFLAGS) $(CFLAGS) $(LDFLAGS) -o harness_example harness_example.o global_state_detector.o $(LDLIBS)

clean:
	rm -f harness_example global_state_detector.o harness_example.o
