import { type Base58, type Keyset, type UnixTimestamp } from '@localfirst/crdx'
import type { Device, FirstUseDevice } from 'device/index.js'

/** Whether an invitation admits a new member or a new device for an existing member. */
export type InvitationKind = 'member' | 'device'

/**
 * The public record of the invitation that Alice adds to the signature chain after inviting Bob
 * (or, that Bob's laptop adds after inviting Bob's phone).
 * */
export type Invitation = {
  /** Public, unique identifier for the invitation */
  id: Base58

  /** The public signing key derived from the secret invitation key */
  publicKey: Base58

  /** Time when the invitation expires. If 0, the invitation does not expire. */
  expiration: UnixTimestamp

  /** Number of times the invitation can be used. If 0, the invitation can be used any number of times. */
  maxUses: number

  /** (Device invitations only) The user the invited device will belong to. This is the *only*
   * source of a new device's owner — an invitee never supplies its own. */
  userId?: string
}

/**
 * The current state of the invitation; appears in the Team state. These properties are populated
 * by the reducer.
 * */
export type InvitationState = {
  /** Whether this invitation admits a member or a device. Derived from the graph action that
   * posted it, not from anything the invitee claims. */
  kind: InvitationKind

  /** Number of times the invitation has been used */
  uses: number

  /** If true, this invitation was revoked at some point after it was created (but before it was used) */
  revoked: boolean
} & Invitation

/** The identity a member invitation admits: a new user plus the initial device they'll use. */
export type MemberInvitationClaim = {
  invitationKind: 'member'
  userName: string
  memberKeys: Keyset
  device: Device
}

/**
 * The identity a device invitation admits. It carries no `userId`, by design: the owner comes from
 * the authenticated invitation record, so an invitee can't name a user it wasn't invited to join.
 */
export type DeviceInvitationClaim = {
  invitationKind: 'device'
  device: FirstUseDevice
  userName?: never
  memberKeys?: never
}

/** The identity fields an invitation proof and a possession proof are both bound to. */
export type InvitationClaim = MemberInvitationClaim | DeviceInvitationClaim

/**
 * The document an invitee presents the first time they connect to an admin, to prove that they've
 * been invited.
 *
 * The signature covers the invitation id, both peers' handshake nonces, and the exact identity
 * being registered — so a proof can't be replayed on another connection or reused to register
 * different keys. It proves only that the holder knows the invitation seed, which the *inviter*
 * also knows; possession of the device keys is proven separately (see `createPossessionProof`).
 * */
export type ProofOfInvitation = {
  /** Public, unique identifier for the invitation */
  id: Base58

  /** Nonce chosen by the peer accepting the invitation */
  acceptorNonce: Base58

  /** Nonce chosen by the invitee */
  inviteeNonce: Base58

  /** Signature over `invitationProofPayload`, using the signing key derived from the secret
   * invitation seed */
  signature: Base58
}
