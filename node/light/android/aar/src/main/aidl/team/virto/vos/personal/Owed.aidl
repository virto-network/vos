// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** What a membership waits for on this device. */
@Backing(type="byte")
enum Owed {
    /** Another of the person's devices to enroll there, by this device's owner proof. */
    ENROLL = 0,
    /** This device's own confirmation there, once its leaf is in. */
    CONFIRM = 1,
}
