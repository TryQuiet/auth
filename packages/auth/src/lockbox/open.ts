import { assert, memoize } from '@localfirst/shared'
import { type KeysetWithSecrets } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { type Lockbox } from 'lockbox/types.js'

export const open = memoize(
  (lockbox: Lockbox, decryptionKeys: KeysetWithSecrets): KeysetWithSecrets => {
    const { encryptionKey, encryptedPayload } = lockbox

    const decrypted = asymmetric.decryptBytes({
      cipher: encryptedPayload,
      senderPublicKey: encryptionKey.publicKey,
      recipientSecretKey: decryptionKeys.encryption.secretKey,
    })
    const keys = decrypted as unknown as KeysetWithSecrets

    // The manifest is used for authorization before the encrypted payload can be opened. Bind the
    // two representations here so an author cannot advertise an established key in `contents`
    // while hiding a conflicting keyset in the ciphertext.
    assert(
      keys.type === lockbox.contents.type &&
        keys.name === lockbox.contents.name &&
        keys.generation === lockbox.contents.generation &&
        keys.encryption.publicKey === lockbox.contents.publicKey,
      'The lockbox contents do not match its manifest'
    )

    return keys
  }
)
