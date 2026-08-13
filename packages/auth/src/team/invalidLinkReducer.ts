import { toOwnedDevice } from 'device/index.js'
import { type DeviceRecord, type Member, type TeamLink, type TeamState } from './types.js'

/**
 * This function is used as an alternative reducer for invalid links. When the normal reducer comes
 * across invalid links, it defers to this function.
 *
 * Invalid links are actions that were flagged to be discarded by the MembershipResolver when
 * dealing with conflicting concurrent actions.
 *
 * Example: Bob invited Charlie, but concurrently Alice removed Bob from the team. Bob's invitation
 * of Charlie is now invalid, as well as anything resulting from that invitation (e.g. Charlie is
 * admitted, Charlie does stuff, etc.)
 *
 * Normally we just ignore these links and they don't affect state at all. However, there are some
 * situations where we need to pay attention. In the above example, we need to act as if Charlie was
 * removed from the team, and do some cleanup.
 */
export const invalidLinkReducer = (state: TeamState, link: TeamLink): TeamState => {
  const { type, payload } = link.body
  switch (type) {
    case 'ADMIT_MEMBER': {
      // We need to treat invalidated ADMIT_MEMBER actions as removals, in that they're included in
      // `removedMembers`. This way their client will receive the appropriate error message when
      // trying to connect, and will know to self-destruct the chain they received.
      const { claim } = payload
      const keys = claim.memberKeys
      const userId = keys.name

      const member: Member = {
        userName: claim.userName,
        userId,
        keys,
        roles: [],
      }

      return {
        ...state,
        // Note that we don't need to alter the list of members, because this member is never added
        removedMembers: [...state.removedMembers, member],
        // The device that came in with them is tombstoned too — it was never registered, but its id
        // must not become available to anyone else.
        removedDevices: tombstone(state, { ...claim.device, admittedAt: link.body.timestamp }),
        // We also need to flag the user as compromised, so that an admin can rotate all keys they
        // had access to at the first opportunity.
        pendingKeyRotations: flagForRotation(state, userId),
      }
    }

    case 'ADMIT_DEVICE': {
      // The member is unaffected — only this device's admission was reversed — but the device had
      // access to whatever its owner could see, so the owner's keys need rotating.
      const { claim, id } = payload
      const userId = state.invitations[id]?.userId
      const device = toOwnedDevice(claim.device, userId ?? '')

      return {
        ...state,
        removedDevices: tombstone(state, { ...device, admittedAt: link.body.timestamp }),
        pendingKeyRotations:
          userId === undefined ? state.pendingKeyRotations : flagForRotation(state, userId),
      }
    }

    default: {
      return state
    }
  }
}

const tombstone = (state: TeamState, device: DeviceRecord) =>
  state.removedDevices.some(d => d.deviceId === device.deviceId)
    ? state.removedDevices
    : [...state.removedDevices, { ...device, removedAt: device.admittedAt }]

const flagForRotation = (state: TeamState, userId: string) =>
  state.pendingKeyRotations.includes(userId)
    ? state.pendingKeyRotations
    : [...state.pendingKeyRotations, userId]
