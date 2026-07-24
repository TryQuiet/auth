import { type Invitation, type InvitationKind } from 'invitation/index.js'
import { type Transform } from 'team/types.js'

export const postInvitation =
  (invitation: Invitation, kind: InvitationKind): Transform =>
  state => {
    const invitationState = {
      ...invitation,
      kind,
      uses: 0,
      revoked: false,
    }

    return {
      ...state,
      invitations: {
        ...state.invitations,
        [invitation.id]: invitationState,
      },
    }
  }
