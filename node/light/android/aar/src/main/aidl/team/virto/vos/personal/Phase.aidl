// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** Where the device's personal space is. */
@Backing(type="byte")
enum Phase {
    NONE = 0,
    CLAIMING = 1,
    JOINING = 2,
    HELD = 3,
    RESTORING = 4,
    REMOVED = 5,
    STUCK = 6,
    NEEDS_REPAIR = 7,
}
