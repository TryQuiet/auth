import { append, createKeyset } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

const FUTURE_ROLE = 'future-role'

describe('future-role lockbox pre-seeding', () => {
  it('does not select a non-admin pre-seeded key after the role is created', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })

    const preseededKeys = createKeyset(
      { type: KeyType.ROLE, name: FUTURE_ROLE },
      'bob-pre-seeds-a-nonexistent-role'
    )
    preseededKeys.generation = 1
    const preseed = append({
      graph: bob.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: {
          lockboxes: [lockbox.create(preseededKeys, alice.team.members(alice.userId).keys)],
        },
      } as TeamAction,
      signer: bob.signer,
      keys: bob.team.teamKeys(),
    })

    alice.team.merge(preseed)
    alice.team.addRole(FUTURE_ROLE)

    const selectedKeys = alice.team.roleKeys(FUTURE_ROLE)
    expect(selectedKeys.generation).toBe(0)
    expect(selectedKeys.encryption.publicKey).not.toBe(preseededKeys.encryption.publicKey)
  })
})
