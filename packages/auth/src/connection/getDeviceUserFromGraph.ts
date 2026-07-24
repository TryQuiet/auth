import type { Keyring, UserWithSecrets } from '@localfirst/crdx'
import { assert, type Logger } from '@localfirst/shared'
import { deriveId } from 'invitation/deriveId.js'
import { generateStarterKeys } from 'invitation/generateStarterKeys.js'
import type { TeamState } from 'team/index.js'
import { KeyType } from 'util/index.js'
import { getTeamState } from '../team/getTeamState.js'
import * as select from '../team/selectors/index.js'

const { USER } = KeyType

/**
 * If we're joining as a new device for an existing member, we don't have a user object yet, so we
 * need to get those from the graph. We use the invitation seed to generate the starter keys for the
 * new device. We can use these to unlock a lockbox on the team graph that contains our user keys.
 */
export const getDeviceUserFromGraph = ({
  serializedGraph,
  teamKeyring,
  invitationSeed,
  logger,
}: {
  serializedGraph: Uint8Array
  teamKeyring: Keyring
  invitationSeed: string
  logger: Logger
}): UserWithSecrets => {
  const state = getTeamState(serializedGraph, teamKeyring, logger)
  return getDeviceUserFromState({ state, invitationSeed })
}

export const getDeviceUserFromState = ({
  state,
  invitationSeed,
}: {
  state: TeamState
  invitationSeed: string
}): UserWithSecrets => {
  const starterKeys = generateStarterKeys(invitationSeed)
  const invitationId = deriveId(invitationSeed)
  const { userId } = select.getInvitation(state, invitationId)
  assert(userId) // since this is a device invitation the invitation info includes the userId that created it

  const { userName } = select.member(state, userId)
  assert(userName) // this user must exist in the team graph

  const userKeys = select.keys(state, starterKeys, { type: USER, name: userId })

  return {
    userName,
    userId,
    keys: userKeys,
  }
}
