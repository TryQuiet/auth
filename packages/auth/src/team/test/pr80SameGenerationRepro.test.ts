import { append, createKeyring, createKeyset } from '@localfirst/crdx'
import { symmetric } from '@localfirst/crypto'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { expect, it } from 'vitest'

it('drops same-generation role-key replacement after removal', () => {
  const { alice, bob } = setup('alice', { user: 'bob', admin: false })
  const originalTeamKeys = alice.team.teamKeys()
  const channel = 'private-channel-role'

  alice.team.addRole(channel)
  alice.team.addMemberRole(bob.userId, channel)
  bob.team = teams.load(
    serializeTeamGraph(alice.team.graph),
    bob.localContext,
    createKeyring(originalTeamKeys)
  )

  alice.team.removeMemberRole(bob.userId, channel)
  const legitimateKeys = alice.team.roleKeys(channel)
  bob.team.merge(alice.team.graph)
  expect(() => bob.team.roleKeys(channel)).toThrow()

  const evilKeys = createKeyset(
    { type: KeyType.ROLE, name: channel },
    'bob-controls-the-replacement'
  )
  evilKeys.generation = 1
  const currentRoleLockbox = bob.team.state.lockboxes.find(
    ({ contents }) =>
      contents.type === KeyType.ROLE &&
      contents.name === channel &&
      contents.generation === legitimateKeys.generation
  )
  expect(currentRoleLockbox).toBeDefined()
  const forgedLockbox = lockbox.create(evilKeys, currentRoleLockbox!.recipient)
  const attack = append({
    graph: bob.team.graph,
    action: { type: 'ADD_LOCKBOXES', payload: { lockboxes: [forgedLockbox] } } as TeamAction,
    signer: bob.signer,
    keys: bob.team.teamKeys(),
  })

  expect(() => alice.team.merge(attack)).not.toThrow()
  expect(alice.team.roleKeys(channel).encryption.publicKey).toBe(
    legitimateKeys.encryption.publicKey
  )

  const message = alice.team.encrypt('secret after removal', channel)
  expect(() => symmetric.decryptBytes(message.contents, evilKeys.secretKey)).toThrow()
  expect(symmetric.decryptBytes(message.contents, legitimateKeys.secretKey)).toBe(
    'secret after removal'
  )

  // The authorization check reads the public manifest before recipients can decrypt the payload.
  // Lying in that manifest must not let the conflicting encrypted key through or poison key lookup.
  const disguisedLockbox = lockbox.create(evilKeys, currentRoleLockbox!.recipient)
  disguisedLockbox.contents.publicKey = legitimateKeys.encryption.publicKey
  const disguisedAttack = append({
    graph: bob.team.graph,
    action: { type: 'ADD_LOCKBOXES', payload: { lockboxes: [disguisedLockbox] } } as TeamAction,
    signer: bob.signer,
    keys: bob.team.teamKeys(),
  })

  expect(() => alice.team.merge(disguisedAttack)).not.toThrow()
  expect(alice.team.roleKeys(channel).encryption.publicKey).toBe(
    legitimateKeys.encryption.publicKey
  )
})
