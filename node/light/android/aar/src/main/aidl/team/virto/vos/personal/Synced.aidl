// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Notice;
import team.virto.vos.personal.Seen;

/**
 * One pass of the facility's sync, the background job's: the enrollments synced and failed (the
 * personal space's pass counted with them), the bytes its connections read and wrote, its length,
 * what the chrome raises, each of the person's devices' last call at the personal agent, and why
 * each failure failed ({@code ; } between them, no secret in it).
 */
parcelable Synced {
    int enrollments;
    int synced;
    int failed;
    long bytesDown;
    long bytesUp;
    long millis;
    Notice[] notices;
    Seen[] seen;
    String failures;
}
