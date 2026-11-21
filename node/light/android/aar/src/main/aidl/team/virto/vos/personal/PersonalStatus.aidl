// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Home;
import team.virto.vos.personal.KitKind;
import team.virto.vos.personal.Notice;
import team.virto.vos.personal.Phase;
import team.virto.vos.personal.Tor;

/**
 * The personal space's state, read without a request: its phase (a restore's maturing at
 * {@code matures}), its home (none: zeros, no onion), agent and this device's id, Tor's state and
 * why it is blocked, the memberships owed, the notices standing, what needs repair, the kind of
 * kit a kit's call here enters (a restore's, else the device set's; known when {@code kitKnown}),
 * and why the last personal pass failed (empty when it did not), standing until a pass changes it.
 */
parcelable PersonalStatus {
    Phase phase;
    long matures;
    Home home;
    long agent;
    long device;
    Tor tor;
    String torWhy;
    int owed;
    Notice[] standing;
    String repair;
    KitKind kit;
    boolean kitKnown;
    String failed;
}
