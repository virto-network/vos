// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/**
 * A device of the person's set: its id and label, whether its admin is strong, its standing (0
 * probation, 1 active, 2 removed, 3 dropped), its last call the agent took (0 before any), whether a
 * removal of it matured, whether it is this device, and whether its add waits for the votes of a
 * pending candidate (no other live device of the set yet).
 */
parcelable Device {
    long id;
    String label;
    boolean strong;
    byte standing;
    long seen;
    boolean removed;
    boolean me;
    boolean adding;
}
