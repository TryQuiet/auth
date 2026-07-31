import * as Auth from '@localfirst/auth'
import type { ShareId } from '@localfirst/auth-provider-automerge-repo'

export const parseInvitationCode = (invitationCode: string) => {
  const [expectedTeamId, invitationSeed] = invitationCode.split(':') as [
    Auth.Base58,
    Auth.Base58,
  ]
  const shareId = expectedTeamId.slice(0, 12) as ShareId
  return { expectedTeamId, shareId, invitationSeed }
}
