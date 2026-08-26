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
 * derive validated team state from the serialized graph and recover the user from it.
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
}): UserWithSecrets =>
  getDeviceUserFromState({
    state: getTeamState(serializedGraph, teamKeyring, logger),
    invitationSeed,
  })

/**
 * Recovers an invited device's user from already-derived team state. The invitation seed gives us
 * both the invitation id and the starter keys that open the lockbox holding the user's keys — and
 * the *owner* comes from the invitation record on the graph, never from anything we claimed.
 */
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
