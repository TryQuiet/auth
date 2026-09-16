import { type Keyset, type KeysetWithSecrets } from '@localfirst/crdx'
import {
  isBase58KeyOfLength,
  isValidEncryptionKeypair,
  isValidSignatureKeypair,
} from '@localfirst/crypto'

/** Strict runtime validation for the plaintext format stored inside a lockbox. */
export function isValidKeyset(value: unknown): value is KeysetWithSecrets {
  if (!isRecord(value)) return false
  if (
    !hasExactKeys(value, ['type', 'name', 'generation', 'secretKey', 'encryption', 'signature'])
  ) {
    return false
  }

  return (
    metadataIsValid(value) &&
    isBase58KeyOfLength(value.secretKey, 32) &&
    isValidEncryptionKeypair(value.encryption) &&
    isValidSignatureKeypair(value.signature)
  )
}

/** Runtime validation for redacted recipient keysets accepted by `lockbox.create`. */
export function isValidPublicKeyset(value: unknown): value is Keyset {
  if (!isRecord(value)) return false
  if (!hasExactKeys(value, ['type', 'name', 'generation', 'encryption', 'signature'])) {
    return false
  }

  return (
    metadataIsValid(value) &&
    isBase58KeyOfLength(value.encryption, 32) &&
    isBase58KeyOfLength(value.signature, 32)
  )
}

export function assertValidKeyset(
  value: unknown,
  message = 'The lockbox keyset is invalid'
): asserts value is KeysetWithSecrets {
  if (!isValidKeyset(value)) throw new Error(message)
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
