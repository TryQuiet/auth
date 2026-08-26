import { createKeyset } from '@localfirst/crdx'
import { describe, expect, it } from 'vitest'
import * as select from '../index.js'
import * as lockbox from 'lockbox/index.js'
import { ADMIN } from 'role/index.js'
import { KeyType, getScope } from 'util/index.js'
import { setup } from 'util/testing/index.js'

const { USER, TEAM, ROLE } = KeyType

describe('visibleKeys', () => {
  it('alice can see admin and team keys', () => {
    const { alice } = setup('alice', { user: 'bob', admin: false })
    const keysAliceSees = select.visibleKeys(alice.team.state, alice.user.keys)
    expect(keysAliceSees.map(getScope)).toEqual([
      { type: TEAM, name: TEAM },
      { type: ROLE, name: ADMIN },
    ])
  })

  it('bob can only see team keys', () => {
    const { bob } = setup('alice', { user: 'bob', admin: false })
    const keysBobKeys = select.visibleKeys(bob.team.state, bob.user.keys)
    expect(keysBobKeys.map(getScope)).toEqual([{ type: TEAM, name: TEAM }])
  })

  it('admin role can see team keys', () => {
    const { alice } = setup('alice')
    alice.team.addRole('MANAGERS')
    const adminKeys = alice.team.adminKeys()
    const keysAdminSees = select.visibleKeys(alice.team.state, adminKeys)
    expect(keysAdminSees.map(getScope)).toEqual([{ type: ROLE, name: 'MANAGERS' }])
  })

  it('admin role can see all other role keys', () => {
    const { alice } = setup('alice')
    alice.team.addRole('MANAGERS')
    const adminKeys = alice.team.adminKeys()
    const keysAdminSees = select.visibleKeys(alice.team.state, adminKeys)
    expect(keysAdminSees.map(getScope)).toEqual([{ type: ROLE, name: 'MANAGERS' }])
  })

  it('after rotating keys, can still see the same scopes', () => {
    const { alice } = setup('alice')
    const getUserKeys = () => select.visibleKeys(alice.team.state, alice.user.keys).map(getScope)

    expect(getUserKeys()).toEqual([
      { type: TEAM, name: TEAM },
      { type: ROLE, name: ADMIN },
    ])

    // Rotating the keys creates new lockboxes, but we don't see duplicate keys
    alice.team.changeKeys(createKeyset({ type: USER, name: alice.userId }))
    expect(getUserKeys()).toEqual([
      { type: TEAM, name: TEAM },
      { type: ROLE, name: ADMIN },
    ])
  })

  it('terminates when an exact keyset is redistributed to itself', () => {
    const { alice } = setup('alice')
    const selfRedistribution = lockbox.create(alice.user.keys, alice.user.keys)
    const state = { ...alice.team.state, lockboxes: [selfRedistribution] }

    expect(select.visibleKeys(state, alice.user.keys)).toEqual([])
  })

  it('terminates a two-keyset cycle without returning the starting keyset', () => {
    const first = createKeyset({ type: 'TEST', name: 'first' }, 'cycle-first')
    const second = createKeyset({ type: 'TEST', name: 'second' }, 'cycle-second')
    const { alice } = setup('alice')
    const state = {
      ...alice.team.state,
      lockboxes: [lockbox.create(second, first), lockbox.create(first, second)],
    }

    expect(select.visibleKeys(state, first)).toEqual([second])
  })

  it('returns duplicate exact redistributions only once', () => {
    const first = createKeyset({ type: 'TEST', name: 'first' }, 'duplicate-first')
    const second = createKeyset({ type: 'TEST', name: 'second' }, 'duplicate-second')
    const third = createKeyset({ type: 'TEST', name: 'third' }, 'duplicate-third')
    const { alice } = setup('alice')
    const state = {
      ...alice.team.state,
      lockboxes: [
        lockbox.create(second, first),
        lockbox.create(second, first),
        lockbox.create(third, second),
        lockbox.create(third, second),
      ],
    }

    expect(select.visibleKeys(state, first)).toEqual([second, third])
  })
})
