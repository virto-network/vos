// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** A claim's, a restore's result: the agent, and this device's id in its set. */
parcelable Claimed {
    long agent;
    long device;
}
