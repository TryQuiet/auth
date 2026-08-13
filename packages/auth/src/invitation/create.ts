import { type UnixTimestamp } from '@localfirst/crdx'
import { generateStarterKeys } from './generateStarterKeys.js'
import { deriveId } from 'invitation/deriveId.js'
import { normalize } from 'invitation/normalize.js'
import { type Invitation } from 'invitation/types.js'

export const IKEY_LENGTH = 16

/**
 * Returns an an invitation to publicly post on the team's signature chain. Inspired by Keybase's
 * Seitan Token v2 exchange protocol.
 */
export const create = ({
  seed,
  expiration = 0 as UnixTimestamp, // By default an invitation never expires
  userId,
}: Params): Invitation => {
  seed = normalize(seed)

  // The ID of the invitation is derived from the seed
  const id = deriveId(seed)

  // The ephemeral public signature key will be used to verify Bob's proof of invitation
  const starterKeys = generateStarterKeys(seed)
  const { publicKey } = starterKeys.signature

  return { id, publicKey, expiration, userId }
}

type Params = {
  /** A randomly generated secret to be passed to Bob via a side channel */
  seed: string

  /** Time when the invitation expires. If 0, the invitation does not expire. */
  expiration?: UnixTimestamp

  /** (Device invitations only) User name the device will be associated with. */
  userId?: string
}
