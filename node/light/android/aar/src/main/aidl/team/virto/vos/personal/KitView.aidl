// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.vos.personal.Device;
import team.virto.vos.personal.Notice;

/** The device set as the kit reads it at its home: each device, and the operations open. */
parcelable KitView {
    Device[] devices;
    Notice[] operations;
}
