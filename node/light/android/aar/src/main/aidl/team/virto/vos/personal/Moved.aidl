// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** `moveHome`'s result: the new agent, and the envelopes carried there. */
parcelable Moved {
    long agent;
    long carried;
}
