// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Alarm;
import team.virto.vos.personal.Pending;
import team.virto.vos.personal.Remedy;

/**
 * One thing the chrome raises: an operation's at its log index, taken at {@code at} (the agent's
 * time, 0 when this pass did not read it) and maturing at {@code matures} unless vetoed, signed by
 * device {@code by} or by the kit ({@code byKit}), {@code contested} by another (a contest this
 * device cannot resolve when {@code targeted}, the kit alone when {@code kitOnly}); a restore
 * stopped, at its log index; or an alarm of its kind, {@code index} its place and its
 * {@code remedy}. {@code fresh} when no pass raised it before, so its notification alerts.
 */
parcelable Notice {
    Pending pending;
    long index;
    long at;
    long matures;
    boolean fresh;
    long by;
    boolean byKit;
    boolean contested;
    Alarm alarm;
    Remedy remedy;
    boolean targeted;
    boolean kitOnly;
}
