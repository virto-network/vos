// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** What a device that cannot follow its group does. */
@Backing(type="byte")
enum Remedy {
    NONE = 0,
    RE_PAIR = 1,
    REGROUP = 2,
}
