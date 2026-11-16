// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** A pairing's result: the new device's id, and the memberships owed for it. */
parcelable Paired {
    long device;
    int memberships;
}
