// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** What alarm a notice raises. */
@Backing(type="byte")
enum Alarm {
    NONE = 0,
    LOG = 1,
    SPLIT_LOG = 2,
    NAMED_ABSENT = 3,
    REFUSED = 4,
    CANNOT_FOLLOW = 5,
    VERDICT = 6,
    UNSIGNED = 7,
    CLOCK = 8,
    KIT = 9,
    ROLLBACK = 10,
    VIEW = 11,
    DROPPED = 12,
    PARTITION = 13,
    WITHHELD = 14,
    STALE = 15,
    AUTHOR = 16,
    DELETED = 17,
    UNSERVED = 18,
    POLICY = 19,
}
