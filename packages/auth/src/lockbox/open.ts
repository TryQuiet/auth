import { assert } from '@localfirst/shared'
import { type KeysetWithSecrets } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { keysetCommitment } from 'lockbox/keysetCommitment.js'
import { isKeyManifest, isRecipientManifest, type Lockbox } from 'lockbox/types.js'
import { assertValidKeyset } from 'lockbox/validateKeyset.js'

export const open = (lockbox: Lockbox, decryptionKeys: KeysetWithSecrets): KeysetWithSecrets => {
  const { encryptionKey, encryptedPayload } = lockbox
  assertValidKeyset(decryptionKeys, 'The lockbox decryption keys are invalid')
  assert(isRecipientManifest(lockbox.recipient), 'The lockbox recipient manifest is invalid')
  assert(isKeyManifest(lockbox.contents), 'The lockbox contents manifest is invalid')

  assert(
    lockbox.recipient.type === decryptionKeys.type &&
      lockbox.recipient.name === decryptionKeys.name &&
      lockbox.recipient.generation === decryptionKeys.generation &&
      lockbox.recipient.publicKey === decryptionKeys.encryption.publicKey,
    'The lockbox recipient does not match its decryption keys'
  )

  const decrypted = asymmetric.decryptBytes({
    cipher: encryptedPayload,
    senderPublicKey: encryptionKey.publicKey,
    recipientSecretKey: decryptionKeys.encryption.secretKey,
  })
  assertValidKeyset(decrypted, 'The lockbox contents are not a valid keyset')
  const keys = decrypted

  // The manifest is used for authorization before the encrypted payload can be opened. Bind the
  // two representations here so an author cannot advertise an established key in `contents`
  // while hiding a conflicting keyset in the ciphertext.
  assert(
    keys.type === lockbox.contents.type &&
      keys.name === lockbox.contents.name &&
      keys.generation === lockbox.contents.generation &&
      keys.encryption.publicKey === lockbox.contents.publicKey &&
      keysetCommitment(keys) === lockbox.contents.commitment,
    'The lockbox contents do not match its manifest'
  )

  return keys
}
