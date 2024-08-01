import { type Keyring, type KeysetWithSecrets, createKeyring } from '@localfirst/crdx'
import { type TeamGraph } from './types.js'
import { type LocalContext } from 'team/context.js'
import { Team } from 'team/Team.js'

export const load = (
  source: Uint8Array | TeamGraph,
  context: LocalContext,
  teamKeys: KeysetWithSecrets | Keyring
) => {
  let start, end: number
  start = Date.now()
  const teamKeyring = createKeyring(teamKeys)
  end = Date.now()
  console.log(`Time to create keyring: ${end - start}ms`)
  start = Date.now()
  const team = new Team({ source, context, teamKeyring })
  end = Date.now()
  console.log(`Time to create team: ${end - start}ms`)
  return team
}
