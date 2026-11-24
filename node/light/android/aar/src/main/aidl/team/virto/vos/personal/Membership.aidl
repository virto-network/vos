// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Owed;

/**
 * A membership in a space other than the home, what is owed there, and, once this device is
 * enrolled there ({@code enrolled}), the space's name as its gateway gave it at the enrollment.
 */
parcelable Membership {
    byte[] space;
    byte[] handle;
    long agent;
    long instance;
    Owed owed;
    boolean enrolled;
    String name;
}
