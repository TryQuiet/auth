import { createKeyset } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import type { TeamAction } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { KeyType } from 'util/index.js'
import { describe, expect, it } from 'vitest'
import { forge } from './forgeHelpers.js'

describe('unsafe role names', () => {
  it.each(['__proto__', 'constructor', 'prototype'])(
    'rejects a signed and encrypted %s role on another replica without mutating state',
    roleName => {
      const { alice, bob } = setup('alice', 'bob')
      const roleKeys = createKeyset({ type: KeyType.ROLE, name: roleName }, `unsafe-${roleName}`)
      const action = {
        type: 'ADD_ROLE',
        payload: {
          roleName,
          createdBy: alice.userId,
          lockboxes: [lockbox.create(roleKeys, alice.team.adminKeys())],
        },
      } as TeamAction
      const hostileGraph = forge({
        graph: alice.team.graph,
        action,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })
      const graphBefore = bob.team.graph
      const rolesBefore = bob.team.roles()
      const teamKeysBefore = bob.team.teamKeys()
      const prototypeBefore = Object.getOwnPropertyDescriptor(Object.prototype, '0')
      const objectBefore = Object.getOwnPropertyDescriptor(Object, '0')

      expect(() => bob.team.merge(hostileGraph)).toThrow(/Role name .* is reserved/)
      expect(bob.team.graph).toEqual(graphBefore)
      expect(bob.team.roles()).toEqual(rolesBefore)
      expect(bob.team.teamKeys()).toEqual(teamKeysBefore)
      expect(Object.getOwnPropertyDescriptor(Object.prototype, '0')).toEqual(prototypeBefore)
      expect(Object.getOwnPropertyDescriptor(Object, '0')).toEqual(objectBefore)
    }
  )
})
