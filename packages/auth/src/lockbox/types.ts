import { type KeyMetadata } from '@localfirst/crdx'
import { isBase58KeyOfLength, type Base58 } from '@localfirst/crypto'

export const KEY_MANIFEST_VERSION = 1 as const

/** Public metadata needed to identify and encrypt to a lockbox recipient. */
export type RecipientManifest = KeyMetadata & {
  publicKey: Base58
}

/** A versioned commitment to every security-relevant field of the encrypted keyset. */
export type KeyManifest = RecipientManifest & {
  version: typeof KEY_MANIFEST_VERSION
  commitment: Base58
}

export const isRecipientManifest = (value: unknown): value is RecipientManifest => {
  if (!isRecord(value)) return false
  if (!hasExactKeys(value, ['type', 'name', 'generation', 'publicKey'])) return false

  return metadataIsValid(value) && isBase58KeyOfLength(value.publicKey, 32)
}

export const isKeyManifest = (value: unknown): value is KeyManifest => {
  if (!isRecord(value)) return false
  if (!hasExactKeys(value, ['type', 'name', 'generation', 'publicKey', 'version', 'commitment'])) {
    return false
  }

  return (
    metadataIsValid(value) &&
    isBase58KeyOfLength(value.publicKey, 32) &&
    value.version === KEY_MANIFEST_VERSION &&
    isBase58KeyOfLength(value.commitment, 32)
  )
}

export type Lockbox = {
  /** The public key of the keypair used to encrypt this lockbox  */
  encryptionKey: {
    type: 'EPHEMERAL'
    publicKey: Base58
  }

  /** Manifest for the keyset that can open this lockbox (the lockbox recipient's keys) */
  recipient: RecipientManifest

  /** Manifest for the keyset that is in this lockbox (the lockbox contents) */
  contents: KeyManifest

  /** The encrypted keyset */
  encryptedPayload: Uint8Array
}

const metadataIsValid = (value: Record<string, unknown>) =>
  typeof value.type === 'string' &&
  value.type.length > 0 &&
  typeof value.name === 'string' &&
  value.name.length > 0 &&
  typeof value.generation === 'number' &&
  Number.isSafeInteger(value.generation) &&
  value.generation >= 0

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (value: Record<string, unknown>, expected: string[]) => {
  const actual = Object.keys(value)
  return actual.length === expected.length && expected.every(key => Object.hasOwn(value, key))
}
