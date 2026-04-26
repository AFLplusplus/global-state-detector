/*
 * Example integration in a LLVMFuzzerTestOneInput harness.
 *
 * Build:
 *   make
 *
 * Run with a single input to see what state a target carries:
 *   ./harness_example -runs=50 corpus/
 *
 * The probe will report writable global state changed by target_process().
 * Rebaselining immediately before the target call avoids reporting libFuzzer's
 * own bookkeeping mutations between callbacks.
 */

#include "global_state_detector.h"
#include <stddef.h>
#include <stdint.h>


/* Your target's API - adapt as needed. */
unsigned long target_accumulator = 0;

void target_process(const uint8_t *data, size_t size) {

  for (size_t i = 0; i < size; ++i)
    target_accumulator += data[i];

}


int LLVMFuzzerInitialize(int *argc, char ***argv) {

  (void)argc;
  (void)argv;

  /* If your target has one-time process setup, do it here. The detector
   * snapshot is taken in LLVMFuzzerTestOneInput so libFuzzer can finish its
   * own startup first. */
  /* target_init(); */

  return 0;

}


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
