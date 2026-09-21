import { assert } from '@localfirst/shared'
import { type TeamState } from 'team/types.js'

/** Returns whether exactly one active member has this userId; throws when the id is ambiguous. */
export const hasMember = (state: TeamState, userId: string) => {
  const matchingMembers = state.members.filter(member => member.userId === userId)
  assert(matchingMembers.length <= 1, `Member ID '${userId}' is ambiguous`)
  return matchingMembers.length === 1
}
