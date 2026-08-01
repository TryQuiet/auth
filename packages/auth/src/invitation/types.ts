import type { Base58, Keyset, UnixTimestamp } from '@localfirst/crdx'
import type { Device, FirstUseDevice } from 'device/index.js'

export type InvitationKind = 'member' | 'device'

type InvitationBase = {
  /** Public, unique identifier for the invitation */
  id: Base58

  /** Time when the invitation expires. If 0, the invitation does not expire. */
  expiration: UnixTimestamp

  /** Number of times the invitation can be used. If 0, the invitation can be used any number of times. */
  maxUses: number

  /** (Device invitations only) User id the device will be associated with. */
  userId?: string
}

/** Legacy invitation record. It remains readable but is not accepted without an explicit legacy mode. */
export type InvitationV1 = InvitationBase & {
  version?: 1
  publicKey: Base58
}

/** Invitation record for the transcript-bound admission protocol. */
export type InvitationV2 = InvitationBase & {
  version: 2
  signaturePublicKey: Base58
  encryptionPublicKey: Base58
}

/** Public invitation record added to the authenticated team graph. */
export type Invitation = InvitationV1 | InvitationV2

/** Current reduced state of an invitation. */
export type InvitationState = {
  /** Whether this invitation admits a new member or a new device. Derived from its graph action. */
  kind: InvitationKind

  /** Number of times the invitation has been used */
  uses: number

  /** Whether this invitation was revoked after creation. */
  revoked: boolean
} & Invitation

export type MemberInvitationClaim = {
  invitationKind: 'member'
  userName: string
  userKeys: Keyset
  device: Device
}

export type DeviceInvitationClaim = {
  invitationKind: 'device'
  userName: string
  device: FirstUseDevice
  userKeys?: never
}

/** Identity fields cryptographically bound to an invitation proof. */
export type InvitationClaim = MemberInvitationClaim | DeviceInvitationClaim

export type ProofOfInvitationV1 = {
  version?: 1
  id: Base58
  signature: Base58
}

export type ProofOfInvitationV2 = {
  version: 2
  id: Base58
  acceptorNonce: Base58
  inviteeNonce: Base58
  signature: Base58
}

export type ProofOfInvitation = ProofOfInvitationV1 | ProofOfInvitationV2
