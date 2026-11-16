// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

/** The QR code to show: its bytes, which hold the pairing's one-time code, and the slot's expiry. */
parcelable PairCode {
    byte[] code;
    long expiresMs;
}
