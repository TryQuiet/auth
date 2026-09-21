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

      // Exception: a *duplicate* admission of someone who was validly admitted on another branch is
      // not a reversal — the resolver collapsed two registrations of one identity to converge, and
      // the surviving admission already registered this member. Treating the dropped duplicate as a
      // removal would tombstone the live member (and their device), so we no-op instead.
      if (isValidlyRegisteredMember(state, userId)) return state

      const member: Member = {
        userName: claim.userName,
        userId,
        keys,
        roles: [],
      }

      return {
        ...state,
        // Note that we don't need to alter the list of members, because this member is never added
        removedMembers: tombstoneMember(state, member),
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

      // As with ADMIT_MEMBER: a duplicate admission of a device already registered on another branch
      // is convergence, not a reversal, so it must not tombstone the live device.
      if (isValidlyRegisteredDevice(state, claim.device.deviceId)) return state

      const userId = state.invitations[id]?.userId
      const device = toOwnedDevice(claim.device, userId ?? '')

      return {
        ...state,
        removedDevices: tombstone(state, { ...device, admittedAt: link.body.timestamp }),
        pendingKeyRotations:
          userId === undefined ? state.pendingKeyRotations : flagForRotation(state, userId),
      }
    }

    case 'INVITE_MEMBER':
    case 'INVITE_DEVICE': {
      // Keep a revoked record for an invalid invitation. Besides making its id permanently
      // unusable, this preserves a device invitation's owner for a dependent invalid admission,
      // whose cleanup must tombstone the exposed device and rotate the owner's keys.
      const { invitation } = payload
      if (state.invitations[invitation.id] !== undefined) return state
      const kind = type === 'INVITE_MEMBER' ? 'member' : 'device'
      return {
        ...state,
        invitations: {
          ...state.invitations,
          [invitation.id]: { ...invitation, kind, revoked: true },
        },
      }
    }

    default: {
      return state
    }
  }
}

/** True if this member is a live (non-removed) member of the team. */
const isValidlyRegisteredMember = (state: TeamState, userId: string) =>
  state.members.some(member => member.userId === userId)

/** True if this device is a live (non-tombstoned) device of some current member. */
const isValidlyRegisteredDevice = (state: TeamState, deviceId: string) =>
  state.members.some(member => (member.devices ?? []).some(device => device.deviceId === deviceId))

const tombstoneMember = (state: TeamState, member: Member) =>
  state.removedMembers.some(({ userId }) => userId === member.userId)
    ? state.removedMembers
    : [...state.removedMembers, member]

const tombstone = (state: TeamState, device: DeviceRecord) =>
  state.removedDevices.some(d => d.deviceId === device.deviceId)
    ? state.removedDevices
    : [...state.removedDevices, { ...device, removedAt: device.admittedAt }]

const flagForRotation = (state: TeamState, userId: string) =>
  state.pendingKeyRotations.includes(userId)
    ? state.pendingKeyRotations
    : [...state.pendingKeyRotations, userId]
