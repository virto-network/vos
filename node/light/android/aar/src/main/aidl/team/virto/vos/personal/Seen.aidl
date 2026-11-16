// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** A device of the person's set, and its last call the personal agent took (0 before any). */
parcelable Seen {
    long device;
    long at;
}
