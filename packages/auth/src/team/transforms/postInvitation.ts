import { type Invitation, type InvitationKind } from 'invitation/index.js'
import { type Transform } from 'team/types.js'

/**
 * Records an invitation.
 *
 * `kind` comes from the graph action that posted it (INVITE_MEMBER vs INVITE_DEVICE), never from
 * anything an invitee claims — that's what lets the admission validators reject a device invitation
 * being cashed in as a member admission, or vice versa.
 */
export const postInvitation =
  (invitation: Invitation, kind: InvitationKind): Transform =>
  state => ({
    ...state,
    invitations: {
      ...state.invitations,
      [invitation.id]: { ...invitation, kind, uses: 0, revoked: false },
    },
  })
