// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** An admin call the personal agent took: its log index and its batch time. */
parcelable Posted {
    long index;
    long at;
}
