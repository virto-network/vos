// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/**
 * Where a flow is, said to the screen that runs it (`IVosWatcher.stage`): a kind alone, no secret
 * and no value in it, in no order a flow keeps.
 */
@Backing(type="byte")
enum Stage {
    /** Reaching the home: its open claim, an agent from its pool. */
    REACHING = 1,
    /** The device's proof made for its home. */
    PROVING = 2,
    /** The recovery kit written at the agent. */
    WRITING_KIT = 3,
    /** The device set's log followed: the group joined or caught up. */
    JOINING = 4,
    /** A pairing's code read by the new device. */
    SCANNED = 5,
    /** A pairing's check confirmed. */
    CHECKED = 6,
    /** The device set's keys handed over to the new device. */
    HANDING_OVER = 7,
    /** The new device's add waiting for the opener's admin key. */
    APPROVING = 8,
    /** This device's leave taken: the space being forgotten. */
    LEAVING = 9,
}
