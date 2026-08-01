import { createKeyset, redactKeys } from '@localfirst/crdx'
import { createDevice, redactDevice } from 'device/index.js'
import { redactUser } from 'team/redactUser.js'
import * as select from 'team/selectors/index.js'
import type { TeamState } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('team identity invariants', () => {
  it('rejects a duplicate active member ID', () => {
    const { alice, bob } = setup('alice', 'bob')
    const duplicate = alice.team.members(bob.userId)

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_MEMBER',
        payload: { member: duplicate },
      })
    ).toThrow(/already in use/)
    expect(alice.team.members().filter(member => member.userId === bob.userId)).toHaveLength(1)
  })

  it('rejects duplicate device IDs within one member and across members', () => {
    const { alice, bob } = setup('alice', 'bob')
    const aliceDevice = redactDevice(alice.device)

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_DEVICE',
        payload: { device: aliceDevice },
      })
    ).toThrow(/already in use/)

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_DEVICE',
        payload: {
          device: {
            ...aliceDevice,
            userId: bob.userId,
          },
        },
      })
    ).toThrow(/already in use/)
  })

  it('rejects collisions between device IDs and server hosts', () => {
    const { alice } = setup('alice')
    const { deviceId } = alice.device

    expect(() =>
      alice.team.addServer({
        host: deviceId,
        keys: redactKeys(createKeyset({ type: KeyType.SERVER, name: deviceId })),
      })
    ).toThrow(/already in use/)

    const host = 'sync.example.test'
    alice.team.addServer({
      host,
      keys: redactKeys(createKeyset({ type: KeyType.SERVER, name: host })),
    })
    const collidingDevice = createDevice({
      userId: alice.userId,
      deviceName: 'colliding-device',
    })
    collidingDevice.deviceId = host
    collidingDevice.keys.name = host

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_DEVICE',
        payload: { device: redactDevice(collidingDevice) },
      })
    ).toThrow(/already in use/)
  })

  it('rejects mismatched key names, types, and initial generations', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const member = redactUser(bob.user)

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_MEMBER',
        payload: {
          member: {
            ...member,
            keys: { ...member.keys, name: 'not-bob' },
          },
        },
      })
    ).toThrow(/metadata/)

    const phone = redactDevice(alice.phone!)
    expect(() =>
      alice.team.dispatch({
        type: 'ADD_DEVICE',
        payload: {
          device: {
            ...phone,
            keys: {
              ...phone.keys,
              type: KeyType.USER,
              generation: 1,
            },
          },
        },
      })
    ).toThrow(/metadata/)
  })

  it("rejects a non-admin ADD_DEVICE for another member's device", () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const alicePhone = redactDevice(alice.phone!)

    expect(() =>
      bob.team.dispatch({
        type: 'ADD_DEVICE',
        payload: { device: alicePhone },
      })
    ).toThrow(/non-admin/)
    expect(bob.team.hasDevice(alicePhone.deviceId)).toBe(false)
  })

  it('clears member and device tombstones on legitimate re-add', () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.remove(bob.userId)
    expect(alice.team.memberWasRemoved(bob.userId)).toBe(true)

    alice.team.addForTesting(bob.user, [], redactDevice(bob.device))
    expect(alice.team.members().filter(member => member.userId === bob.userId)).toHaveLength(1)
    expect(alice.team.memberWasRemoved(bob.userId)).toBe(false)

    alice.team.removeDevice(bob.device.deviceId)
    expect(alice.team.deviceWasRemoved(bob.device.deviceId)).toBe(true)
    alice.team.addForTesting(bob.user, [], redactDevice(bob.device))
    expect(alice.team.hasDevice(bob.device.deviceId)).toBe(true)
    expect(alice.team.deviceWasRemoved(bob.device.deviceId)).toBe(false)
  })

  it('makes singular selectors fail closed on legacy ambiguous state', () => {
    const { alice, bob } = setup('alice', 'bob')
    const bobMember = alice.team.members(bob.userId)
    const duplicateMemberState: TeamState = {
      ...alice.team.state,
      members: [...alice.team.state.members, bobMember],
    }

    expect(() => select.member(duplicateMemberState, bob.userId)).toThrow(/ambiguous/)
    expect(() => select.hasMember(duplicateMemberState, bob.userId)).toThrow(/ambiguous/)

    const aliceMember = alice.team.members(alice.userId)
    const aliceDevice = aliceMember.devices![0]
    const duplicateDeviceState: TeamState = {
      ...alice.team.state,
      members: alice.team.state.members.map(member =>
        member.userId === alice.userId
          ? {
              ...member,
              devices: [...(member.devices ?? []), { ...aliceDevice }],
            }
          : member
      ),
    }

    expect(() => select.device(duplicateDeviceState, aliceDevice.deviceId)).toThrow(/ambiguous/)
    expect(() => select.memberByDeviceId(duplicateDeviceState, aliceDevice.deviceId)).toThrow(
      /ambiguous/
    )
  })
})
