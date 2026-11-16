// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Pending;

/**
 * One thing the chrome raises: an operation's at its log index, taken at {@code at} (the agent's
 * time, 0 when this pass did not read it) and maturing at {@code matures} unless vetoed;
 * {@code fresh} when no pass raised it before, so its notification alerts.
 */
parcelable Notice {
    Pending pending;
    long index;
    long at;
    long matures;
    boolean fresh;
    String detail;
}
