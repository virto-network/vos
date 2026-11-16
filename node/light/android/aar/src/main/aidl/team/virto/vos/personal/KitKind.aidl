// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** What a recovery kit is. */
@Backing(type="byte")
enum KitKind {
    /** 24 words, shown once in the chrome and written down. */
    PHRASE = 1,
    /** A FIDO2 security key's `hmac-secret`. */
    SECURITY_KEY = 2,
}
