import { assert } from '@localfirst/shared'
import { createKeyring, createUser, type Signer, type UserWithSecrets } from '@localfirst/crdx'
import type { Connection, Context, InviteeContext, MemberContext } from 'connection/index.js'
import type { DeviceWithSecrets } from 'device/index.js'
import * as devices from 'device/index.js'
import { ADMIN } from 'role/index.js'
import type { LocalUserContext } from 'team/context.js'
import type { Team } from 'team/index.js'
import { deviceSigner } from 'team/index.js'
import * as teams from 'team/index.js'
import { arrayToMap, deriveUserId } from 'util/index.js'
import { phoneInfo, laptopInfo } from './constants.js'

export type SetupConfig = Array<Array<TestUserSettings | string> | TestUserSettings | string>

// ignore file coverage

/**
 * Creates a matched user and founding device for tests that build identities by hand, deriving the
 * user's id from the device exactly the way `setup` and the real founder/join flows do.
 */
export const createTestUser = (
  userName: string,
  {
    deviceName = 'laptop',
    seed = userName,
    deviceInfo,
  }: { deviceName?: string; seed?: string; deviceInfo?: any } = {}
): { user: UserWithSecrets; device: DeviceWithSecrets } => {
  const laptop = devices.createFirstUseDevice({ deviceName, seed: `${seed}-${deviceName}`, deviceInfo })
  const userId = deriveUserId(laptop.deviceId)
  return {
    user: createUser(userName, userId, seed),
    device: { ...laptop, userId },
  }
}

/**
Usage:

```ts
const {alice, bob} = setup(['alice', 'bob'])
const {alice, bob, charlie} = setup(['alice', 'bob', {user: 'charlie', member: false}])
const {alice, bob, charlie, dwight} = setup(['alice', 'bob', 'charlie', {user: 'dwight', admin: false}])

alice.team.add('bob')
```
*/
export const setup = (..._config: SetupConfig) => {
  assert(_config.length > 0)

  // Accept `setup(['a', 'b'])` or `setup('a','b')`
  if (Array.isArray(_config[0])) {
    _config = _config[0] as Array<TestUserSettings | string>
  }

  // Coerce string userIds into TestUserSettings objects
  const config = _config.map(u => (typeof u === 'string' ? { user: u } : u)) as TestUserSettings[]

  // Get a list of just user ids
  const userNames = config.map(user => user.user)

  // Every user's id is derived from their founding device, so the device has to exist first. A
  // device's id is the fingerprint of its own keys — independent of its owner — so we can mint the
  // laptop, derive the userId from it, and only then create the user (and their phone, a second
  // device under the same derived id). This is uniform for the founder and every member.
  const testUsers: Record<string, UserWithSecrets> = {}
  const laptops: Record<string, DeviceWithSecrets> = {}
  const phones: Record<string, DeviceWithSecrets> = {}
  for (const userName of userNames) {
    const laptop = devices.createFirstUseDevice({
      deviceName: 'laptop',
      seed: `${userName}-laptop`,
      deviceInfo: laptopInfo,
    })
    const userId = deriveUserId(laptop.deviceId)
    laptops[userName] = { ...laptop, userId }
    phones[userName] = devices.createDevice({
      userId,
      deviceName: 'phone',
      seed: `${userName}-phone`,
      deviceInfo: phoneInfo,
    })
    testUsers[userName] = createUser(userName, userId, userName)
  }

  // Create team
  const founder = userNames[0] // E.g. alice

  const founderContext = { user: testUsers[founder], device: laptops[founder] }
  const teamName = 'Spies Я Us'
  const randomSeed = teamName
  const team = teams.createTeam(teamName, founderContext, randomSeed, { selfAssignableRoles: ['MEMBER'] })
  const teamKeys = team.teamKeys()

  // Add members
  for (const { user: userName, admin = true, member = true } of config) {
    const user = testUsers[userName]
    if (member && !team.has(user.userId)) {
      const user = testUsers[userName]
      const roles = admin ? [ADMIN] : []
      const device = devices.redactDevice(laptops[userName])
      team.addForTesting(user, roles, device)
    }
  }

  const { graph } = team

  const makeUserStuff = ({ user: userName, member = true }: TestUserSettings): UserStuff => {
    const user = testUsers[userName]
    const randomSeed = userName
    const device = laptops[userName]
    const phone = phones[userName]

    const localContext = { user, device }
    const team = member
      ? teams.load(graph, localContext, createKeyring(teamKeys)) // Members get a copy of the source team
      : teams.createTeam(userName, localContext, randomSeed) // Non-members get a dummy empty placeholder team

    const connectionContext: Context = member
      ? { user, device, team }
      : { user, device, invitationSeed: '' }

    const phoneStuff: UserStuff = {
      userName,
      userId: user.userId,
      deviceId: phone.deviceId,
      user,
      team: member
        ? teams.load(graph, localContext, createKeyring(teamKeys)) // Members get a copy of the source team
        : teams.createTeam(userName, localContext, randomSeed), // Non-members get a dummy empty placeholder team
      device: phone,
      localContext: { user, device: phone },
      signer: deviceSigner(phone),
      connectionContext,
      connection: {} as Record<string, Connection>,
      getState: (peer: string) => phoneStuff.connection[peer].state,
    }

    const connection = {} as Record<string, Connection>
    const getState = (peer: string) => connection[peer].state

    return {
      userName: user.userName,
      userId: user.userId,
      deviceId: device.deviceId,
      user,
      team,
      device,
      localContext,
      signer: deviceSigner(device),
      phone,
      phoneStuff,
      connectionContext,
      connection,
      getState,
    }
  }

  const testUserStuff: Record<string, UserStuff> = config
    .map(makeUserStuff)
    .reduce(arrayToMap('userName'), {})

  return testUserStuff
}

// TYPES

export type TestUserSettings = {
  user: string
  admin?: boolean
  member?: boolean
}

export type UserStuff = {
  userName: string
  userId: string
  deviceId: string
  user: UserWithSecrets
  team: Team
  device: DeviceWithSecrets
  phone?: DeviceWithSecrets
  phoneStuff?: UserStuff
  localContext: LocalUserContext

  /** The identity this user's device signs links with, for tests that append to a graph directly. */
  signer: Signer
  connectionContext: MemberContext | InviteeContext
  connection: Record<string, Connection>
  getState: (peer: string) => any
}
