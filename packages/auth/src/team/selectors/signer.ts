import type { SignerInfo } from '@localfirst/crdx'
import { SignerKind, type ResolvedSigner, type TeamState } from 'team/types.js'
import { allDeviceIds } from './device.js'
import { allServerIds } from './server.js'
import { device, hasDevice } from './device.js'
import { hasServer, server } from './server.js'

/**
 * Resolves the identity named in a link's `body.signer` to the record we hold for it, or
 * `undefined` if we don't know it.
 *
 * Removed signers are included on purpose: a link signed by a device that was later removed is a
 * different situation from a link signed by an id nobody has ever registered, and the caller needs
 * to tell them apart. Whether a removed signer may still author is a separate check.
 */
export const signerRecord = (
  state: TeamState,
  signer: SignerInfo,
  options = { includeRemoved: true }
): ResolvedSigner | undefined => {
  if (signer.kind === SignerKind.DEVICE) {
    return hasDevice(state, signer.id, options)
      ? { kind: SignerKind.DEVICE, device: device(state, signer.id, options) }
      : undefined
  }

  if (signer.kind === SignerKind.SERVER) {
    return hasServer(state, signer.id, options)
      ? { kind: SignerKind.SERVER, server: server(state, signer.id, options) }
      : undefined
  }

  return undefined
}

/**
 * Returns true if `id` is already spoken for by any identity the team has ever known — a member, a
 * device (including tombstones), or a server (including removed ones).
 *
 * Ids are global: a device id and a server id and a user id all appear in the same `signer.id`
 * position, so allowing two identities to share one would make "who signed this" ambiguous. Removed
 * identities keep their ids forever, so that a removal can't be undone by re-registering the id.
 */
export const identityIdIsInUse = (state: TeamState, id: string): boolean =>
  [...state.members, ...state.removedMembers].some(member => member.userId === id) ||
  allDeviceIds(state).includes(id) ||
  allServerIds(state).includes(id)
