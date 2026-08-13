// ignore file coverage

import type {
  Base58,
  Keyring,
  KeyScope,
  SyncState,
  UnixTimestamp,
  UserWithSecrets,
} from '@localfirst/crdx'
import type {
  Device,
  DeviceWithSecrets,
  FirstUseDevice,
  FirstUseDeviceWithSecrets,
} from 'device/index.js'
import type { InvitationClaim, ProofOfInvitation } from 'invitation/index.js'
import type { ServerWithSecrets } from 'server/index.js'
import type { Member, Team, TeamState } from 'team/index.js'
import type { ConnectionErrorPayload } from './errors.js'
import type { ConnectionMessage } from './message.js'

export type ConnectionEvents = {
  /** state change in the connection */
  change: (summary: string) => void

  /** message received from peer */
  message: (message: unknown) => void

  /** Our peer has detected an error and reported it to us, e.g. we tried to join with an invalid invitation. */
  remoteError: (error: ConnectionErrorPayload) => void

  /** We've detected an error locally, e.g. a peer tries to join with an invalid invitation. */
  localError: (error: ConnectionErrorPayload) => void

  /** We're connected to a peer and have been mutually authenticated. */
  connected: () => void

  /**
   * We've successfully joined a team using an invitation. This event provides the team graph and
   * the user's info (including keys). (When we're joining as a new device for an existing user,
   * this is how we get the user's keys.) This event gives the application a chance to persist the
   * team graph and the user's info.
   */
  joined: ({ team, user }: { team: Team; user: UserWithSecrets; teamKeyring: Keyring }) => void

  /** The team graph has been updated. This event gives the application a chance to persist the changes. */
  updated: (head: string[]) => void

  /** The auth connection disconnects from a peer after entering an error state. */
  disconnected: (event: ConnectionMessage) => void

  sync: ({ team, user }: { team: Team; user: UserWithSecrets }) => void

  /** Identities have been validated on both ends of the connection and the connection is encrypted */
  connectionSecured: () => void
}

// IDENTITY CLAIMS

export type MemberIdentityClaim = {
  /** I'm already a member; I authenticate as the device I sign links with. */
  deviceId: string
}

export type ServerIdentityClaim = {
  /** I'm a server; I authenticate as my immutable identity keys, never as my host. */
  serverId: string
}

/**
 * What an invitee presents instead of authenticating: the exact identity it wants registered, a
 * proof that it holds the invitation seed, and a proof that it holds the keys in the claim.
 *
 * All three travel verbatim to `Team.admitMember` / `Team.admitDevice`, which post them on the
 * graph, so every other replica re-derives the admitted identity from the same signed material
 * the admitting peer saw.
 */
export type InviteeIdentityClaim = {
  proofOfInvitation: ProofOfInvitation

  /** The identity being registered. Both proofs are signed over exactly this object. */
  claim: InvitationClaim

  /** Signature by the new device's own signing key over the claim; only the invitee can make it. */
  possessionProof: Base58
}

export type IdentityClaim = MemberIdentityClaim | ServerIdentityClaim | InviteeIdentityClaim

// CONTEXT

export type MemberContext = {
  user: UserWithSecrets
  device: DeviceWithSecrets
  team: Team
}

export type InviteeMemberContext = {
  user: UserWithSecrets
  device: DeviceWithSecrets
  invitationSeed: string
}

export type InviteeDeviceContext = {
  userName: string
  device: FirstUseDeviceWithSecrets
  invitationSeed: string
}

export type InviteeContext = InviteeMemberContext | InviteeDeviceContext

export type ServerContext = {
  server: ServerWithSecrets
  team: Team
}

export type Context = MemberContext | InviteeContext | ServerContext

export type Challenge = KeyScope & {
  nonce: Base58
  timestamp: UnixTimestamp
}

/** An `ACCEPT_INVITATION` payload, along with the team state we derived from it. */
export type InvitationAcceptance = {
  serializedGraph: Uint8Array
  teamKeyring: Keyring

  /** Undefined if the graph didn't deserialize or didn't validate. */
  state?: TeamState
}

export type ConnectionContext = {
  /** Our device — absent on a server, since a server signs as itself rather than as a device. */
  device?: DeviceWithSecrets | FirstUseDeviceWithSecrets

  /** Present only when we're a server. */
  server?: ServerWithSecrets

  /**
   * Our member identity. On a server this is the server's projection as a member; on a device
   * joining with an invitation it's unknown until we've read it out of the team graph.
   */
  user?: UserWithSecrets

  /** The user an invited device expects to belong to. Display only — the owner comes from the
   * invitation record on the graph. */
  userName?: string

  team?: Team

  invitationSeed?: string

  /** Nonce we sent with `REQUEST_IDENTITY`; an invitee's proof to us must be bound to it. */
  acceptorNonce: Base58

  /** Nonce we bind our own invitation proof to. */
  inviteeNonce: Base58

  ourIdentityClaim?: IdentityClaim
  theirIdentityClaim?: IdentityClaim

  challenge?: Challenge

  theirDevice?: Device | FirstUseDevice
  peer?: Member

  /** The invitation acceptance we received, and the team state we derived from it. */
  acceptance?: InvitationAcceptance

  seed?: Uint8Array
  sessionKey?: Uint8Array

  syncState?: SyncState

  error?: ErrorPayload
}

export type ErrorPayload = {
  message: string
  details?: any
}

// TYPE GUARDS

// initial context

type C = Context | ConnectionContext

export const isMemberContext = (c: C): c is MemberContext => {
  return 'team' in c && c.team !== undefined && !isServerContext(c)
}

export const isInviteeContext = (c: C): c is InviteeContext => {
  return 'invitationSeed' in c && c.invitationSeed !== undefined
}

export const isInviteeMemberContext = (c: C): c is InviteeMemberContext => {
  return isInviteeContext(c) && 'user' in c && c.user !== undefined
}

export const isInviteeDeviceContext = (c: C): c is InviteeDeviceContext => {
  return isInviteeContext(c) && !isInviteeMemberContext(c)
}

export const isServerContext = (c: C): c is ServerContext => {
  return 'server' in c && c.server !== undefined
}

// identity claim

export const isMemberClaim = (claim: IdentityClaim): claim is MemberIdentityClaim => {
  return 'deviceId' in claim && claim.deviceId !== undefined
}

export const isServerClaim = (claim: IdentityClaim): claim is ServerIdentityClaim => {
  return 'serverId' in claim && claim.serverId !== undefined
}

export const isInviteeClaim = (claim: IdentityClaim): claim is InviteeIdentityClaim => {
  return 'proofOfInvitation' in claim && claim.proofOfInvitation !== undefined
}

export const isInviteeMemberClaim = (
  claim: IdentityClaim
): claim is InviteeIdentityClaim & { claim: { invitationKind: 'member' } } => {
  return isInviteeClaim(claim) && claim.claim.invitationKind === 'member'
}

export const isInviteeDeviceClaim = (
  claim: IdentityClaim
): claim is InviteeIdentityClaim & { claim: { invitationKind: 'device' } } => {
  return isInviteeClaim(claim) && claim.claim.invitationKind === 'device'
}
