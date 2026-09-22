import { type KeysetWithSecrets } from '@localfirst/crdx'
import { CheckedKeyStore } from './CheckedKeyStore.js'
import { type Lockbox } from './types.js'

export const open = (lockbox: Lockbox, decryptionKeys: KeysetWithSecrets): KeysetWithSecrets => {
  const keys = new CheckedKeyStore().open(lockbox, decryptionKeys)
  // The standalone API returns caller-owned material; Team keeps its checked records private.
  return { ...keys, encryption: { ...keys.encryption }, signature: { ...keys.signature } }
}
