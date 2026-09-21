import { EPHEMERAL_SCOPE, type Keyset, type KeysetWithSecrets, redactKeys } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { keysetCommitment } from 'lockbox/keysetCommitment.js'
import {
  KEY_MANIFEST_VERSION,
  isKeyManifest,
  isRecipientManifest,
  type KeyManifest,
  type Lockbox,
  type RecipientManifest,
} from 'lockbox/types.js'
import { assertValidKeyset, isValidKeyset, isValidPublicKeyset } from 'lockbox/validateKeyset.js'

/** Creates a new lockbox that can be opened using the recipient's private key. */
export const create = (
  contents: KeysetWithSecrets,
  recipientKeys: KeysetWithSecrets | Keyset | RecipientManifest | KeyManifest
): Lockbox => {
  assertValidKeyset(contents, 'The lockbox contents must be a valid keyset')

  // Retain only the recipient metadata needed to identify and encrypt to this exact generation.
  const recipient = recipientManifest(recipientKeys)

  // Generate a new single-use keypair to encrypt the lockbox with
  const encryptionKeys = asymmetric.keyPair()

  // Encrypt the lockbox's contents
  const encryptedPayload = asymmetric.encryptBytes({
    secret: contents,
    recipientPublicKey: recipient.publicKey,
    senderSecretKey: encryptionKeys.secretKey,
  })

  return {
    encryptionKey: {
      ...EPHEMERAL_SCOPE,
      type: 'EPHEMERAL',
      publicKey: encryptionKeys.publicKey,
    },
    recipient,
    contents: {
      type: contents.type,
      name: contents.name,
      generation: contents.generation,
      publicKey: contents.encryption.publicKey,
      version: KEY_MANIFEST_VERSION,
      commitment: keysetCommitment(contents),
    },
    encryptedPayload,
  }
}

const recipientManifest = (
  keys: KeysetWithSecrets | Keyset | RecipientManifest | KeyManifest
): RecipientManifest => {
  if (isRecipientManifest(keys)) return { ...keys }
  if (isKeyManifest(keys)) {
    return {
      type: keys.type,
      name: keys.name,
      generation: keys.generation,
      publicKey: keys.publicKey,
    }
  }

  if (!isValidKeyset(keys) && !isValidPublicKeyset(keys)) {
    throw new Error('The lockbox recipient keys are invalid')
  }

  const redacted = redactKeys(keys)
  return {
    type: redacted.type,
    name: redacted.name,
    generation: redacted.generation,
    publicKey: redacted.encryption,
  }
}
