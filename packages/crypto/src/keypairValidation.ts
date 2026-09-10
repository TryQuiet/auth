import sodium from 'libsodium-wrappers-sumo'
import { type Base58, type Base58Keypair } from './types.js'
import { keyToBytes } from './util/index.js'

// Cache only successful correspondence checks, separately for each algorithm. Bound retention of
// secret material, and key by both strings so mutations and freshly decoded copies behave alike.
const CACHE_LIMIT = 256
const encryptionPairs = new Set<string>()
const signaturePairs = new Set<string>()

const remember = (cache: Set<string>, key: string): true => {
  if (cache.size >= CACHE_LIMIT) cache.delete(cache.values().next().value!)
  cache.add(key)
  return true
}

/** Returns whether a value is a Base58-encoded byte string of exactly the requested length. */
export const isBase58KeyOfLength = (value: unknown, expectedLength: number): value is Base58 => {
  if (typeof value !== 'string') return false

  try {
    return keyToBytes(value).length === expectedLength
  } catch {
    return false
  }
}

/**
 * Verifies both the encoded lengths and the public/secret correspondence of a Curve25519
 * encryption keypair.
 */
export const isValidEncryptionKeypair = (value: unknown): value is Base58Keypair => {
  if (!isRecord(value)) return false
  if (!hasExactKeys(value, ['publicKey', 'secretKey'])) return false
  if (!isBase58KeyOfLength(value.publicKey, sodium.crypto_box_PUBLICKEYBYTES)) return false
  if (!isBase58KeyOfLength(value.secretKey, sodium.crypto_box_SECRETKEYBYTES)) return false

  const cacheKey = `${value.publicKey}:${value.secretKey}`
  if (encryptionPairs.has(cacheKey)) return true
  const publicKey = keyToBytes(value.publicKey)
  const derivedPublicKey = sodium.crypto_scalarmult_base(keyToBytes(value.secretKey))
  return sodium.memcmp(publicKey, derivedPublicKey) && remember(encryptionPairs, cacheKey)
}

/**
 * Verifies both the encoded lengths and the public/secret correspondence of an Ed25519 signature
 * keypair. Re-deriving the complete keypair from the secret seed checks both halves of libsodium's
 * 64-byte secret-key representation; merely extracting its embedded public key would not.
 */
export const isValidSignatureKeypair = (value: unknown): value is Base58Keypair => {
  if (!isRecord(value)) return false
  if (!hasExactKeys(value, ['publicKey', 'secretKey'])) return false
  if (!isBase58KeyOfLength(value.publicKey, sodium.crypto_sign_PUBLICKEYBYTES)) return false
  if (!isBase58KeyOfLength(value.secretKey, sodium.crypto_sign_SECRETKEYBYTES)) return false

  const cacheKey = `${value.publicKey}:${value.secretKey}`
  if (signaturePairs.has(cacheKey)) return true
  const publicKey = keyToBytes(value.publicKey)
  const secretKey = keyToBytes(value.secretKey)
  const seed = secretKey.slice(0, sodium.crypto_sign_SEEDBYTES)
  const derived = sodium.crypto_sign_seed_keypair(seed)

  return (
    sodium.memcmp(publicKey, derived.publicKey) &&
    sodium.memcmp(secretKey, derived.privateKey) &&
    remember(signaturePairs, cacheKey)
  )
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (value: Record<string, unknown>, expected: string[]) => {
  const actual = Object.keys(value)
  return actual.length === expected.length && expected.every(key => Object.hasOwn(value, key))
}
