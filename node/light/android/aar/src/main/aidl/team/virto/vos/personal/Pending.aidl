// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** What a local notification raises. */
@Backing(type="byte")
enum Pending {
    /** A device added by a delayed admin. */
    ADD = 0,
    REMOVE = 1,
    /** A device's admin key replaced. */
    REPLACE = 2,
    /** The recovery kit replaced. */
    ROTATE = 3,
    /** Every other device removed and a new group started by one alone. */
    REGROUP = 4,
    /** Every device removed by the kit's restore. */
    RESTORE = 5,
    /** A restore is pending: this device answered it with `alive`. */
    RESTORING = 6,
    /** This device is out of its group. */
    REMOVED = 7,
    /** The personal space raised an alarm, its detail named. */
    ALARM = 9,
    /** This device cannot follow its group: it re-pairs, or regroups. */
    STUCK = 10,
}
