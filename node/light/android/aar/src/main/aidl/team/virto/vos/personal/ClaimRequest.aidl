// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Home;
import team.virto.vos.personal.KitKind;

/**
 * `claim` (and `moveHome`, `restore`): a personal agent at the home with a kit of the kind, this
 * device named `label` to the person's other devices.
 */
parcelable ClaimRequest {
    Home home;
    KitKind kit;
    String label;
}
