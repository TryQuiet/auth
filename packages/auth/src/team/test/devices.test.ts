import * as teams from 'team/index.js'
import { setup as setupUsers } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'

describe('Team', () => {
  const setup = () => {
    const { alice, bob } = setupUsers(['alice', { user: 'bob', admin: false }])
    return { alice, bob }
  }

  describe('devices', () => {
    it('Alice has a device', () => {
      const { alice } = setup()
      expect(alice.team.members(alice.userId).devices).toHaveLength(1)
    })

    it('Bob has a device', () => {
      const { alice, bob } = setup()
      expect(alice.team.members(bob.userId).devices).toHaveLength(1)
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip(`Bob can remove Bob's device`, () => {
      const { bob } = setup()
      bob.team.removeDevice(bob.device.deviceId)
      expect(bob.team.members(bob.userId)?.devices ?? []).toHaveLength(0)
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip("Alice can remove Bob's device", () => {
      const { alice, bob } = setup()
      alice.team.removeDevice(bob.device.deviceId)
      expect(alice.team.members(bob.userId).devices).toHaveLength(0)
    })

    it("Bob cannot remove Alice's device", () => {
      const { alice, bob } = setup()
      const aliceDevice = bob.team.members(alice.userId).devices![0].deviceId
      const tryToRemoveDevice = () => {
        bob.team.removeDevice(aliceDevice)
      }

      expect(tryToRemoveDevice).toThrowError()
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('deviceWasRemoved works as expected', () => {
      const { alice, bob } = setup()
      alice.team.removeDevice(bob.device.deviceId)
      expect(alice.team.deviceWasRemoved(alice.device.deviceId)).toBe(false) // Device still exists
      expect(alice.team.deviceWasRemoved(bob.device.deviceId)).toBe(true) // Device was removed
      expect(alice.team.deviceWasRemoved(bob.phone!.deviceId)).toBe(false) // Device never existed
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('throws when trying to remove a removed device', () => {
      const { alice, bob } = setup()
      const bobDevice = alice.team.members(bob.userId).devices![0].deviceId
      alice.team.removeDevice(bobDevice)

      const removeAgain = () => alice.team.removeDevice(bobDevice)
      expect(removeAgain).toThrow()
    })

    it('throws when trying to remove a nonexistent device', () => {
      const { alice, bob } = setup()
      const _bobDevice = alice.team.members(bob.userId).devices![0].deviceId

      const remove = () => alice.team.removeDevice('pizza')
      expect(remove).toThrow()
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('throws when trying to access a removed device', () => {
      const { alice, bob } = setup()
      const bobDevice = alice.team.members(bob.userId).devices![0].deviceId
      alice.team.removeDevice(bobDevice)

      const getDevice = () => alice.team.device(bobDevice)
      expect(getDevice).toThrow()
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip("doesn't throw when deliberately trying to access a removed device", () => {
      const { alice, bob } = setup()
      const bobDevice = alice.team.members(bob.userId).devices![0].deviceId
      alice.team.removeDevice(bobDevice)

      const getDevice = () => alice.team.device(bobDevice, { includeRemoved: true })
      expect(getDevice).not.toThrow()
    })

    it('can look up a device by deviceId', () => {
      const { alice } = setup()
      const { deviceId } = alice.device
      const aliceDevice = alice.team.device(deviceId)
      expect(aliceDevice.deviceId).toBe(deviceId)
    })

    it('can find a userId by deviceId', () => {
      const { alice } = setup()
      const { deviceId } = alice.device

      const result = alice.team.memberByDeviceId(deviceId)
      expect(result.userId).toBe(alice.userId)
    })

    it('throws when trying to access a nonexistent device', () => {
      const { alice } = setup()
      const getDevice = () => alice.team.device('alicez wrist communicator')
      expect(getDevice).toThrow()
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('has an admin rotate shared keys after a non-admin removes a device', () => {
      const { alice, bob } = setup()

      // Keys have never been rotated
      expect(bob.team.teamKeys().generation).toBe(0)
      const { secretKey } = bob.team.teamKeys()

      // Bob invites his phone and admits it. A device can only join through an invitation now —
      // that's what makes it prove it holds its own keys before anything is registered for it.
      const { seed } = bob.team.inviteDevice()
      bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))

      // The phone instantiates the team and posts a lockbox holding Bob's user keys, which is what
      // gives it access to everything Bob can see
      const phoneTeam = teams.load(
        bob.team.save(),
        { user: bob.user, device: bob.phone! },
        bob.team.teamKeyring()
      )
      phoneTeam.join(bob.team.teamKeyring())
      bob.team.merge(phoneTeam.graph)

      // Remove bob's phone
      bob.team.removeDevice(bob.phone!.deviceId)

      // Bob can rotate his own USER keys, but his shared-key batch is dropped and queued for an
      // admin rather than granting every key holder rotation authority.
      expect(bob.team.teamKeys().generation).toBe(0)
      expect(bob.team.state.pendingKeyRotations).toContain(bob.userId)

      // When an admin receives the removal, it publishes the shared-key rotation. Bob then learns
      // that authorized rotation normally.
      alice.team.merge(bob.team.graph)
      bob.team.merge(alice.team.graph)

      expect(bob.team.teamKeys().generation).toBe(1)
      expect(bob.team.teamKeys().secretKey).not.toBe(secretKey)
      expect(bob.team.state.pendingKeyRotations).not.toContain(bob.userId)
    })
  })
})
