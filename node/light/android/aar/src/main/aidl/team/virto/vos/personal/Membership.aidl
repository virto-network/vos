// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Owed;

/** A membership in a space other than the home, and what is owed there. */
parcelable Membership {
    byte[] space;
    byte[] handle;
    long agent;
    long instance;
    Owed owed;
}
