import { base58 } from '@localfirst/crypto'
import type { Base58, Hash, Keyring, SyncMessage as SyncPayload } from '@localfirst/crdx'
import type { Challenge, IdentityClaim } from 'connection/types.js'
import type { ErrorMessage, LocalErrorMessage } from './errors.js'

export type ReadyMessage = {
  type: 'REQUEST_IDENTITY'
  payload: {
    /**
     * A nonce chosen by the peer asking for our identity. An invitee has to bind its proof of
     * invitation to this, which is why the request carries it: the proof can't be built until the
     * acceptor's nonce has arrived.
     */
    acceptorNonce: Base58
  }
}

/**
 * Runtime validation for the first protocol message, which arrives as untyped wire data.
 *
 * Everything downstream — an invitee's proof of invitation above all — is bound to the nonce this
 * message carries, so a peer that omits or malforms it can't be answered. Rather than crash on the
 * missing field (or, worse, sign over `undefined`), we treat it as a protocol error and disconnect.
 */
export const isReadyMessage = (message: unknown): message is ReadyMessage => {
  if (!isRecord(message) || message.type !== 'REQUEST_IDENTITY' || !isRecord(message.payload)) {
    return false
  }

  const { acceptorNonce } = message.payload
  return typeof acceptorNonce === 'string' && base58.detect(acceptorNonce)
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
  payload: {
    serializedGraph: Uint8Array
    teamKeyring: Keyring
  }
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
