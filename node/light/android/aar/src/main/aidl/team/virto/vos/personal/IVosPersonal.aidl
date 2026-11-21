// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

package team.virto.vos.personal;

import team.virto.s4.vos.IVosPrompts;
import team.virto.s4.vos.Refusal;
import team.virto.vos.personal.ClaimRequest;
import team.virto.vos.personal.Claimed;
import team.virto.vos.personal.Device;
import team.virto.vos.personal.Home;
import team.virto.vos.personal.IVosWatcher;
import team.virto.vos.personal.KitKind;
import team.virto.vos.personal.KitView;
import team.virto.vos.personal.Membership;
import team.virto.vos.personal.Notice;
import team.virto.vos.personal.PairCode;
import team.virto.vos.personal.Paired;
import team.virto.vos.personal.PersonalStatus;
import team.virto.vos.personal.Posted;
import team.virto.vos.personal.Refused;
import team.virto.vos.personal.Synced;

/**
 * The facility's own operations, as its screens and its debug probe call them in the app's
 * processes: the background jobs' passes, Tor's bridges, bootstrap and opt-outs, and the personal
 * space's flows. Served by `VosNodeService` in `:vos` beside s4's `IVosNode`, bound by the intent
 * action `team.virto.vos.personal.IVosPersonal`. An operation that refuses answers null, false or
 * 0 and fills its `out` refusal: the facility's own (the syncs, Tor) s4's `Refusal`, the personal
 * space's a `Refused` the screens branch on; a `RemoteException` means the facility's process
 * stopped. The prompts an operation is lent are s4's `IVosPrompts`.
 */
interface IVosPersonal {
    /** One run of the spaces' sync, apart from every proof: the spaces' background job's. */
    Synced sync(out Refusal refused);

    /** One run of the personal space's sync: its own background job's, on its own circuits. */
    Synced syncPersonal(out Refusal refused);

    /**
     * Bootstrap Tor through the plain bridges pasted in the chrome (none: the public relays), kept
     * for later starts; refused with why (a wrong clock, a bridge that does not answer, a network
     * that blocks Tor).
     */
    boolean bridges(in String[] lines, out Refusal refused);

    /** Bootstrap Tor now (it bootstraps at start too): refused with why, as `bridges` is. */
    boolean bootstrap(out Refusal refused);

    /**
     * Opt the space whose handle this is out of Tor for its key-signed calls, after the chrome
     * showed the warning; or back. Refused for an onion-only space or one with no clearnet port.
     */
    boolean optOut(in byte[] handle, boolean optedOut, out Refusal refused);

    /**
     * The personal space's state, read without a request: what a screen branches on (its phase, a
     * restore's maturity, Tor's state, the memberships owed, the notices standing). Refused only
     * when this facility runs no personal space.
     */
    PersonalStatus status(out Refused refused);

    /** Claim a personal agent at a home-only space, with a kit of the kind asked. */
    Claimed claim(in ClaimRequest request, IVosPrompts prompts, out Refused refused);

    /** Open a pairing slot: the QR code to show. */
    PairCode pairOffer(IVosPrompts prompts, out Refused refused);

    /** Drive the pairing the code shown opened to its end: the new device added. */
    Paired pairAwait(IVosPrompts prompts, out Refused refused);

    /**
     * Cancel the pairing under way (`pairAwait`'s or `pairJoin`'s): it answers its refusal at its
     * next read of the slot.
     */
    void pairCancel();

    /**
     * Join through a scanned code, this device named `label`: one that holds another personal
     * space, or this one's once out of it (its removal matured, as after a regroup), leaves it
     * first; one the set still holds live is refused.
     */
    Paired pairJoin(in byte[] code, String label, IVosPrompts prompts, out Refused refused);

    /** The memberships owed on this device: enrollments of a device it paired, its confirmations. */
    Membership[] memberships(out Refused refused);

    /** Enroll the device a pairing added in the membership's space, by this device's owner proof. */
    boolean enrollDevice(in Membership membership, IVosPrompts prompts, out Refused refused);

    /** This device's own confirmation in the membership's space. */
    boolean confirmDevice(in Membership membership, IVosPrompts prompts, out Refused refused);

    /** Give up an enrollment owed. */
    boolean dropEnrollment(in Membership membership, out Refused refused);

    /** Revoke a removed device's leaf in every space its handles name: how many. */
    int revoke(long device, IVosPrompts prompts, out Refused refused);

    /** The device set, as the personal agent holds it. */
    Device[] devices(out Refused refused);

    /** The device set's operations open. */
    Notice[] operations(out Refused refused);

    /** Remove a device (retire a phone), by the admin key. */
    Posted remove(long device, IVosPrompts prompts, out Refused refused);

    /** Veto an operation open, by the admin key. */
    Posted veto(long index, IVosPrompts prompts, out Refused refused);

    /** Cosign an operation open, which makes it immediate, by the admin key. */
    Posted cosign(long index, IVosPrompts prompts, out Refused refused);

    /** Resolve a contested operation: upheld, or dropped. */
    Posted resolve(long index, boolean upheld, IVosPrompts prompts, out Refused refused);

    /** Rotate the recovery kit to a new one of the kind. */
    Posted rotateKit(KitKind kit, IVosPrompts prompts, out Refused refused);

    /**
     * Replace this device's admin key with a new one (its old key lost, or
     * invalidated by a new biometric), the kit of the kind signing the
     * replacement: it matures after the kit's delay.
     */
    Posted replaceAdmin(KitKind kit, IVosPrompts prompts, out Refused refused);

    /**
     * A new admin key for this device, offered to another seasoned device of the set to sign its
     * replacement (`replaceAdminOf`): the offer's bytes, device (u32 BE) ‖ key ‖ flags ‖ the
     * device's sync-key signature over them, which `replaceAdminOf` checks before it asks.
     */
    byte[] adminOffer(IVosPrompts prompts, out Refused refused);

    /**
     * Another device's admin key replaced by the one its offer names, signed by this device's
     * admin key: a seasoned device other than the one replaced; the new key on its probation.
     */
    Posted replaceAdminOf(in byte[] code, IVosPrompts prompts, out Refused refused);

    /** Remove every other device and start a new group of this one alone. */
    Posted regroup(IVosPrompts prompts, out Refused refused);

    /** Commit now: every matured removal carried, this device's leaf updated. */
    boolean update(IVosPrompts prompts, out Refused refused);

    /**
     * Leave the personal space: this device's own removal, signed by its admin key, read through,
     * then everything this phone kept of the space cleared; the other devices commit it.
     */
    boolean leave(IVosPrompts prompts, out Refused refused);

    /**
     * The commit a matured removal's notice asks for, then each device it removed revoked in every
     * space its handles name (one admin or owner prompt a signature, as each call alone): how many
     * spaces it was revoked in. Refused as the first call that fails; a revoke refused leaves the
     * commit made, the device listed removed for its revoke from the Devices screen.
     */
    int commitRemovals(IVosPrompts prompts, out Refused refused);

    /**
     * Open a restore from the kit of kind `old` at the request's home, a new kit of the request's
     * kind split for it; it matures after the kit's delay unless a device answers.
     */
    Posted restore(in ClaimRequest request, KitKind old, IVosPrompts prompts, out Refused refused);

    /**
     * The device set and its open operations, read under the kit of the kind entered at the agent
     * the home's `Homes` names for it: what a fresh install shows before the kit removes a device
     * or resolves a contest.
     */
    KitView kitView(in Home home, KitKind kit, IVosPrompts prompts, out Refused refused);

    /**
     * Remove a device by the kit of the kind entered, from any install (a lost phone left powered,
     * whose background job would answer every restore): it matures after the kit's delay unless
     * that device vetoes it with its admin key. Called again, a removal whose evidence was lost has
     * it posted.
     */
    Posted removeByKit(in Home home, KitKind kit, long device, IVosPrompts prompts, out Refused refused);

    /** Resolve a contested operation by the kit of the kind entered, at once: upheld, or dropped. */
    Posted resolveByKit(
            in Home home, KitKind kit, long index, boolean upheld, IVosPrompts prompts,
            out Refused refused);

    /**
     * The restore screen's sitting opened: the kit entered in its flows (`restore`, `kitView`,
     * `removeByKit`, `resolveByKit`, `restored`) is held in this process for the next of them, at
     * most ten minutes from its entry, zeroized at `kitForget`, when `token`'s process dies, when
     * the app goes to the background and at its time; never written or logged, never handed back.
     */
    void kitHold(IBinder token);

    /** The sitting closed: the kit held, if any, zeroized. */
    void kitForget();

    /**
     * The screens' watcher, told each flow's stage and each personal pass's end; the one set last
     * is told (null: none).
     */
    void watch(IVosWatcher watcher);

    /** The restore matured: the kit entered again, the personal space read back. */
    Claimed restored(KitKind kit, IVosPrompts prompts, out Refused refused);

    /**
     * Move to another home, carrying nothing: this device leaves the personal space it holds and
     * claims an agent there with a new kit of the kind asked; the other devices pair again.
     */
    Claimed moveHome(in ClaimRequest request, IVosPrompts prompts, out Refused refused);
}
