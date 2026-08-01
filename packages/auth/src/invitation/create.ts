import { type UnixTimestamp } from '@localfirst/crdx'
import { generateStarterKeys } from './generateStarterKeys.js'
import { deriveId } from 'invitation/deriveId.js'
import { normalize } from 'invitation/normalize.js'
import { type InvitationV2 } from 'invitation/types.js'

export const IKEY_LENGTH = 16

/**
 * Normalizes a secret seed and returns a version-2 invitation record to publish on the team graph.
 * The record exposes separate ephemeral signature and encryption public keys derived from the seed.
 * Inspired by Keybase's Seitan Token v2 exchange protocol.
 */
export const create = ({
  seed,
  maxUses = 1, // By default an invitation can only be used once
  expiration = 0 as UnixTimestamp, // By default an invitation never expires
  userId,
}: Params): InvitationV2 => {
  seed = normalize(seed)

  // The ID of the invitation is derived from the seed
  const id = deriveId(seed)

  // The ephemeral public signature key will be used to verify Bob's proof of invitation
  const starterKeys = generateStarterKeys(seed)
  const signaturePublicKey = starterKeys.signature.publicKey
  const encryptionPublicKey = starterKeys.encryption.publicKey

  return {
    version: 2,
    id,
    signaturePublicKey,
    encryptionPublicKey,
    expiration,
    maxUses,
    userId,
  }
}

type Params = {
  /** A randomly generated secret to be passed to Bob via a side channel */
  seed: string

  /** Time when the invitation expires. If 0, the invitation does not expire. */
  expiration?: UnixTimestamp

  /** Number of times the invitation can be used. If 0, the invitation can be used any number of times. By default, an invitation can only be used once. */
  maxUses?: number

  /** (Device invitations only) User ID the device will be associated with. */
  userId?: string
}
