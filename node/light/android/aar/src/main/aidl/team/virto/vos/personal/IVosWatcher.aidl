// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/**
 * The personal space's screens, told by `:vos` as things happen (`IVosPersonal.watch`): a flow's
 * stage while it runs, and each background pass done. Neither carries a secret or a value.
 */
oneway interface IVosWatcher {
    /** The flow under way reached a stage, a `Stage`'s byte. */
    void stage(byte stage);

    /** A pass of the personal space's sync ended: the status it changed is read again. */
    void passed();
}
