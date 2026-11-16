// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.s4.vos.Onion;

/**
 * A home as the device reaches it: its space and handle, the agent holding its credential actor and
 * `Homes` with the identity calls to it are signed for, their instances, and its onions (a home is
 * onion-only).
 */
parcelable Home {
    byte[] space;
    byte[] handle;
    long agent;
    byte[] identity;
    long homes;
    long credentials;
    Onion[] onions;
}
