import { type KeysetWithSecrets } from '@localfirst/crdx'
import { asymmetric, hash, type Payload } from '@localfirst/crypto'
import { assert } from '@localfirst/shared'
import { pack, unpack } from 'msgpackr'
import { isUnsafeScopeName } from '../team/unsafeScopeName.js'
import { keysetCommitment } from './keysetCommitment.js'
import { isLockboxCollection, snapshotLockbox } from './snapshot.js'
import { isKeyManifest, isRecipientManifest, type Lockbox } from './types.js'

type CheckedKeyset = { keys: KeysetWithSecrets; commitment: string }
export type KeyMap = Record<string, Record<string, KeysetWithSecrets[]>>

/** Local cryptographic material owned by one Team. Only the supplied lockboxes determine access;
 * retaining a checked key or delivery never makes it selectable in another state.
 */
export class CheckedKeyStore {
  /** Pinned material: the owner's own lockbox keys and the contents of successful deliveries. */
  readonly #material = new Map<string, CheckedKeyset>()
  /** Every owned immutable copy, pinned or not. Weak, so a transient lookup key is collectable. */
  readonly #owned = new WeakMap<KeysetWithSecrets, CheckedKeyset>()
  readonly #deliveries = new Map<string, CheckedKeyset>()
  #selection?: { lockboxes: Lockbox[]; recipient: string; keys: KeyMap }

  /** Copy caller-owned data before checking it. Only our immutable records bypass import checks.
   * An import is not retained: explicit lookup keys live only as long as the caller's use of them.
   */
  import(keys: KeysetWithSecrets): KeysetWithSecrets {
    return this.#check(keys).keys
  }

  /** Import and retain for the store's lifetime. Only the owner's own lockbox keys are pinned. */
  pin(keys: KeysetWithSecrets): KeysetWithSecrets {
    return this.#retain(this.#check(keys)).keys
  }

  #check(keys: KeysetWithSecrets): CheckedKeyset {
    const owned = this.#owned.get(keys)
    if (owned !== undefined) return owned
    const checked = checkKeyset(keys)
    const record = this.#material.get(checked.commitment) ?? checked
    this.#owned.set(record.keys, record)
    return record
  }

  #retain(checked: CheckedKeyset): CheckedKeyset {
    const record = this.#material.get(checked.commitment) ?? checked
    this.#material.set(record.commitment, record)
    this.#owned.set(record.keys, record)
    return record
  }

  open(input: Lockbox, decryptionKeys: KeysetWithSecrets): KeysetWithSecrets {
    const recipient = this.#check(decryptionKeys)
    const lockbox = snapshotLockbox(input)
    const { encryptionKey, encryptedPayload, contents } = lockbox
    // Bind the complete owned delivery and checked recipient. A known contents commitment alone
    // cannot authenticate a different ciphertext, manifest, or recipient.
    const delivery = hash('localfirst-auth/checked-key-delivery', [
      encryptionKey,
      lockbox.recipient,
      contents,
      encryptedPayload,
      recipient.commitment,
    ] as Payload)
    const previous = this.#deliveries.get(delivery)
    if (previous !== undefined) return previous.keys

    assert(isRecipientManifest(lockbox.recipient), 'The lockbox recipient manifest is invalid')
    assert(isKeyManifest(contents), 'The lockbox contents manifest is invalid')
    const { keys } = recipient
    assert(
      lockbox.recipient.type === keys.type &&
        lockbox.recipient.name === keys.name &&
        lockbox.recipient.generation === keys.generation &&
        lockbox.recipient.publicKey === keys.encryption.publicKey,
      'The lockbox recipient does not match its decryption keys'
    )
    const checked = checkKeyset(
      asymmetric.decryptBytes({
        cipher: encryptedPayload,
        senderPublicKey: encryptionKey.publicKey,
        recipientSecretKey: keys.encryption.secretKey,
      }),
      'The lockbox contents are not a valid keyset'
    )
    assert(
      checked.keys.type === contents.type &&
        checked.keys.name === contents.name &&
        checked.keys.generation === contents.generation &&
        checked.keys.encryption.publicKey === contents.publicKey &&
        checked.commitment === contents.commitment,
      'The lockbox contents do not match its manifest'
    )
    const record = this.#retain(checked)
    this.#deliveries.set(delivery, record)
    return record.keys
  }

  visibleKeys(lockboxes: Lockbox[], decryptionKeys: KeysetWithSecrets): KeysetWithSecrets[] {
    const root = this.#check(decryptionKeys)
    const visited = new Set([root.commitment])
    const byRecipient = new Map<string, Lockbox[]>()
    for (const lockbox of lockboxes) {
      const address = lockbox.recipient.publicKey
      const deliveries = byRecipient.get(address) ?? []
      deliveries.push(lockbox)
      byRecipient.set(address, deliveries)
    }
    const visit = (recipient: KeysetWithSecrets): KeysetWithSecrets[] => {
      const keys: KeysetWithSecrets[] = []
      for (const lockbox of byRecipient.get(recipient.encryption.publicKey) ?? []) {
        try {
          const opened = this.open(lockbox, recipient)
          const { commitment } = this.#owned.get(opened)!
          if (visited.has(commitment)) continue
          visited.add(commitment)
          keys.push(opened)
        } catch {
          // An unusable delivery must not prevent other reachable keys from being selected.
        }
      }
      return [...keys, ...keys.flatMap(visit)]
    }
    return visit(root.keys)
  }

  keyMap(lockboxes: Lockbox[], decryptionKeys: KeysetWithSecrets): KeyMap {
    const recipient = this.#check(decryptionKeys)
    const previous = this.#selection
    if (previous?.lockboxes === lockboxes && previous.recipient === recipient.commitment)
      return previous.keys

    const keys: KeyMap = Object.create(null)
    for (const key of this.visibleKeys(lockboxes, recipient.keys)) {
      const { type, name, generation } = key
      if (isUnsafeScopeName(type) || isUnsafeScopeName(name)) continue
      keys[type] ??= Object.create(null)
      const scopes = keys[type]
      scopes[name] ??= []
      const generations = scopes[name]
      // Preserve the established generation even for a caller-supplied legacy state.
      if (!Object.hasOwn(generations, generation)) generations[generation] = key
    }
    for (const scopes of Object.values(keys)) {
      for (const generations of Object.values(scopes)) Object.freeze(generations)
      Object.freeze(scopes)
    }
    Object.freeze(keys)
    // Mutable arrays always select afresh. Keep only one view, rather than all replay states.
    if (isLockboxCollection(lockboxes)) {
      this.#selection = { lockboxes, recipient: recipient.commitment, keys }
    }
    return keys
  }
}

const checkKeyset = (input: unknown, message = 'The lockbox keyset is invalid'): CheckedKeyset => {
  const keys = unpack(pack(input)) as KeysetWithSecrets
  // keysetCommitment validates the complete shape and both public/secret correspondences.
  let commitment: string
  try {
    commitment = keysetCommitment(keys)
  } catch {
    throw new Error(message)
  }
  Object.freeze(keys.encryption)
  Object.freeze(keys.signature)
  Object.freeze(keys)
  return { keys, commitment }
}
