// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Why;

/**
 * Why a personal operation was refused: its kind, a device it names (the one that regrouped), and
 * its detail (an agent's error's name, a store's failure): no prose the screen shows as it is.
 */
parcelable Refused {
    Why why;
    long device;
    String detail;
}
