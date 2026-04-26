/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * global_state_detector.h - public API for writable global-state detection
 * Copyright (C) 2026 Marc "vanHauser" Heuse <vh@thc.org>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

#ifndef GLOBAL_STATE_DETECTOR_H
#define GLOBAL_STATE_DETECTOR_H

#ifdef __cplusplus
extern "C" {

#endif

/* Snapshot all writable PT_LOAD segments of the main binary and every
 * currently loaded shared object. Call once after the target has been
 * fully initialized (i.e. after any one-time setup your harness does). */
void global_state_detector_init(void);

/* Diff current memory against the last snapshot.
 * Returns the number of pages that changed.
 * If rebaseline != 0, the snapshot is updated to the current state so
 * the next call only shows new deltas. */
int global_state_detector_check(int rebaseline);

/* Force a full re-snapshot without reporting. */
void global_state_detector_rebaseline(void);

#ifdef __cplusplus

}

#endif

#endif
