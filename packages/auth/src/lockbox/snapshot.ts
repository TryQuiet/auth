import { type Lockbox } from './types.js'

// Only reducer-owned snapshots may be cached by identity. A frozen Uint8Array is not possible,
// and Object.freeze(lockbox) alone does not protect its bytes or nested manifests.
const snapshots = new WeakSet<Lockbox>()
const collections = new WeakSet<Lockbox[]>()

export const snapshotLockbox = (lockbox: Lockbox): Lockbox => {
  if (snapshots.has(lockbox)) return lockbox
  const bytes = new Uint8Array(lockbox.encryptedPayload)
  const snapshot: Lockbox = Object.freeze({
    encryptionKey: Object.freeze({ ...lockbox.encryptionKey }),
    recipient: Object.freeze({ ...lockbox.recipient }),
    contents: Object.freeze({ ...lockbox.contents }),
    get encryptedPayload() {
      return new Uint8Array(bytes)
    },
  })
  snapshots.add(snapshot)
  return snapshot
}

export const isLockboxSnapshot = (lockbox: Lockbox) => snapshots.has(lockbox)
export const isLockboxCollection = (lockboxes: Lockbox[]) => collections.has(lockboxes)

export const snapshotLockboxes = (lockboxes: Lockbox[]): Lockbox[] => {
  if (collections.has(lockboxes)) return lockboxes
  const snapshot = lockboxes.map(snapshotLockbox)
  Object.freeze(snapshot)
  collections.add(snapshot)
  return snapshot
}

/** Copy only newly accepted lockboxes; existing snapshots are already immutable. */
export const appendLockboxes = (previous: Lockbox[], added: Lockbox[]): Lockbox[] => {
  const before = snapshotLockboxes(previous)
  const after = before.concat(added.map(snapshotLockbox))
  Object.freeze(after)
  collections.add(after)
  return after
}
