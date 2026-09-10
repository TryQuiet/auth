import sodium from 'libsodium-wrappers-sumo'
import { pack } from 'msgpackr'
import { stretch } from './stretch.js'
import { type Base58, type Payload, type SignedMessage } from './types.js'
import { base58, keypairToBase58, keyToBytes } from './util/index.js'
import { isValidSignatureKeypair } from './keypairValidation.js'

/**
 * @returns A key pair consisting of a public key and a secret key, encoded as base58 strings, to
 * use for signing and verifying messages. (Note that signature keys cannot be used for asymmetric
 * encryption, and vice versa.)
 */
const keyPair = (seed?: string) => {
  const keypair = seed
    ? sodium.crypto_sign_seed_keypair(stretch(seed))
    : sodium.crypto_sign_keypair()
  return keypairToBase58(keypair)
}

/**
 * Binds a payload to a domain-separation context before signing or verifying. The context string
 * and the payload are packed together as a msgpack tuple `[context, payload]`; because msgpack
 * length-prefixes the context string, there is no ambiguity about where the context ends and the
 * payload begins, so a signature made under one context cannot verify under another. Crucially the
 * context is bound OUTSIDE the payload, so an attacker who can get a victim to sign an arbitrary
 * payload in one context still cannot produce a signature valid in another.
 */
const packWithContext = (payload: Payload, context: string): Uint8Array => {
  if (context.length === 0) {
    throw new Error('A non-empty domain-separation context is required to sign or verify')
  }

  return pack([context, payload])
}

/**
 * @param payload The message to sign
 * @param secretKey The signer's secret key, encoded as a base58 string
 * @param context A domain-separation tag identifying the purpose of this signature (see
 *   `./domains.js`). Signing and verifying must use the same context; this prevents a signature
 *   made for one purpose from being replayed as valid for another (cross-context forgery).
 * @returns A signature, encoded as a base58 string
 */
const sign = (payload: Payload, secretKey: Base58, context: string) => {
  const payloadBytes = packWithContext(payload, context)
  const secretKeyBytes = keyToBytes(secretKey)
  const signatureBytes = sodium.crypto_sign_detached(payloadBytes, secretKeyBytes)
  return base58.encode(signatureBytes)
}

/**
 * @returns true if verification succeeds, false otherwise. Verification fails unless `context`
 *   matches the domain-separation tag the signature was produced under.
 */
const verify = ({ payload, signature, publicKey, context }: SignedMessage): boolean => {
  const payloadBytes = packWithContext(payload, context)
  const signatureBytes = keyToBytes(signature)
  const publicKeyBytes = keyToBytes(publicKey)
  return sodium.crypto_sign_verify_detached(signatureBytes, payloadBytes, publicKeyBytes)
}

export const signatures = { keyPair, keyPairIsValid: isValidSignatureKeypair, sign, verify }
