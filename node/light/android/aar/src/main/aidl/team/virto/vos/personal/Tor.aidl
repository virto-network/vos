// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** Tor as the process's client last found it. */
@Backing(type="byte")
enum Tor {
    STARTING = 0,
    CONNECTED = 1,
    BLOCKED = 2,
}
