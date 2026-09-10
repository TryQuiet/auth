import * as select from 'team/selectors/index.js'
import { SignerKind, type TeamLink, type TeamState, type Transform } from 'team/types.js'

/**
 * A member may replace their own USER keys or remove one of their own devices, but only an admin may
 * rotate the shared TEAM/ROLE keys that identity could reach. Record the affected identity so the
 * next admin replica to reduce the action publishes the required shared-key rotation.
 */
export const requestAdminKeyRotation =
  (link: TeamLink): Transform =>
  state => {
    const userId = rotationTarget(state, link)
    if (userId === undefined || authorIsAdmin(state, link)) return state
    if (state.pendingKeyRotations.includes(userId)) return state

    return {
      ...state,
      pendingKeyRotations: [...state.pendingKeyRotations, userId],
    }
  }

const rotationTarget = (state: TeamState, link: TeamLink): string | undefined => {
  const { type, payload } = link.body
  if (type === 'CHANGE_MEMBER_KEYS') return payload.keys.name
  if (type !== 'REMOVE_DEVICE') return undefined

  return state.members.find(member =>
    member.devices?.some(device => device.deviceId === payload.deviceId)
  )?.userId
}

const authorIsAdmin = (state: TeamState, link: TeamLink): boolean => {
  const signer = select.signerRecord(state, link.body.signer, { includeRemoved: true })
  if (signer === undefined || signer.kind !== SignerKind.DEVICE) return false
  return select.memberIsAdmin(state, signer.device.userId)
}
