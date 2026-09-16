import { base58 } from '@localfirst/crypto'
import type { Base58, Hash, Keyring, SyncMessage as SyncPayload } from '@localfirst/crdx'
import type { Challenge, IdentityClaim } from 'connection/types.js'
import type { InvitationKind } from 'invitation/index.js'
import type { ErrorMessage, LocalErrorMessage } from './errors.js'

/**
 * Protocol 4 disables removals and key rotation, in addition to protocol 3's complete-keyset
 * lockbox commitments. Negotiate before identity or graph exchange: a protocol 3 replica would
 * apply actions that protocol 4 deliberately leaves inert.
 */
export const CONNECTION_PROTOCOL_VERSION = 4 as const

export type ReadyMessage = {
  type: 'REQUEST_IDENTITY'
  payload: {
    protocolVersion: typeof CONNECTION_PROTOCOL_VERSION

    /**
     * A nonce chosen by the peer asking for our identity. An invitee binds its invitation proof to
     * this exact challenge, so the proof can't be built until the request has arrived.
     */
    identityNonce: Base58
  }
}

/**
 * Runtime validation for the first protocol message, which arrives as untyped wire data.
 *
 * This is also the protocol-version negotiation. The payload is exact so an old implementation
 * cannot ignore an unknown version field and continue under different authorization rules.
 * Everything downstream — an invitee's proof of invitation above all — is bound to the
 * identity nonce this message carries.
 */
export const isReadyMessage = (message: unknown): message is ReadyMessage => {
  if (!isRecord(message) || message.type !== 'REQUEST_IDENTITY' || !isRecord(message.payload)) {
    return false
  }

  const exactWireMessage = hasExactKeys(message, ['index', 'payload', 'type'])
  const exactUnnumberedMessage = hasExactKeys(message, ['payload', 'type'])
  if (!exactUnnumberedMessage && !exactWireMessage) return false
  if (
    exactWireMessage &&
    (typeof message.index !== 'number' || !Number.isSafeInteger(message.index))
  ) {
    return false
  }
  if (!hasExactKeys(message.payload, ['identityNonce', 'protocolVersion'])) return false

  const { identityNonce, protocolVersion } = message.payload
  return (
    protocolVersion === CONNECTION_PROTOCOL_VERSION &&
    typeof identityNonce === 'string' &&
    base58.detect(identityNonce)
  )
}

export type DisconnectMessage = {
  type: 'DISCONNECT'
  payload?: {
    message: string
  }
}

export type RequestResendMessage = {
  type: 'REQUEST_RESEND'
  payload: {
    index: number
  }
}

// Identity

export type ClaimIdentityMessage = {
  type: 'CLAIM_IDENTITY'
  payload: IdentityClaim
}

export type ChallengeIdentityMessage = {
  type: 'CHALLENGE_IDENTITY'
  payload: {
    challenge: Challenge
  }
}

export type ProveIdentityMessage = {
  type: 'PROVE_IDENTITY'
  payload: {
    challenge: Challenge
    proof: Base58 // This is a signature
  }
}

export type AcceptIdentityMessage = {
  type: 'ACCEPT_IDENTITY'
}

export type RejectIdentityMessage = {
  type: 'REJECT_IDENTITY'
  payload: {
    message: string
  }
}

export type AcceptInvitationMessage = {
  type: 'ACCEPT_INVITATION'
  payload: AcceptInvitationPayload
}

/** The sensitive invitation-acceptance body encrypted to the invitation's ephemeral key. */
export type InvitationAcceptanceEnvelope = {
  domain: 'localfirst-auth/invitation-acceptance'
  version: typeof CONNECTION_PROTOCOL_VERSION
  invitationId: Base58
  invitationKind: InvitationKind
  claimDigest: Base58
  identityNonce: Base58
  inviteeNonce: Base58
  acceptorDeviceId: string
  serializedGraph: Uint8Array
  teamKeyring: Keyring
}

/** The non-sensitive outer acceptance message. */
export type AcceptInvitationPayload = {
  version: typeof CONNECTION_PROTOCOL_VERSION
  senderDeviceId: string
  senderPublicKey: Base58
  encryptedAcceptance: Uint8Array
}
// Synchronization

export type SyncMessage = {
  type: 'SYNC'
  payload: SyncPayload
}

// Triggered locally when we detect that team has changed
export type LocalUpdateMessage = {
  type: 'LOCAL_UPDATE'
  payload: { head: Hash[] }
}

// Negotiation

export type SeedMessage = {
  type: 'SEED'
  payload: {
    encryptedSeed: Uint8Array
  }
}

// Communication

export type EncryptedMessage = {
  type: 'ENCRYPTED_MESSAGE'
  payload: Uint8Array
}

export type ConnectionMessage =
  | AcceptIdentityMessage
  | AcceptInvitationMessage
  | ChallengeIdentityMessage
  | ClaimIdentityMessage
  | DisconnectMessage
  | EncryptedMessage
  | ErrorMessage
  | LocalErrorMessage
  | LocalUpdateMessage
  | ProveIdentityMessage
  | ReadyMessage
  | SeedMessage
  | SyncMessage
  | RequestResendMessage

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const actual = Object.keys(value).sort((a, b) => a.localeCompare(b))
  const wanted = [...expected].sort((a, b) => a.localeCompare(b))
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}
