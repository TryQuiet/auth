import { type Logger } from '@localfirst/shared'
import { authorizedLockboxes } from 'team/lockboxAuthorization.js'
import { type TeamLink, type Transform } from 'team/types.js'

/**
 * Sweeps the lockboxes on a link's payload into state — the ones the link is allowed to apply.
 *
 * Any action's payload can carry lockboxes, so this runs for every link. Re-keys of shared (TEAM /
 * ROLE) keys have to be authorized; see `lockboxAuthorization.ts` for what that means and why
 * unauthorized ones are dropped here rather than rejected in `validate`.
 */
export const collectLockboxes =
  (link: TeamLink, logger: Logger): Transform =>
  state => {
    const newLockboxes = link.body.payload.lockboxes
    if (newLockboxes === undefined || newLockboxes.length === 0) return state

    const authorized = authorizedLockboxes(state, link, newLockboxes, logger)
    return { ...state, lockboxes: state.lockboxes.concat(authorized) }
  }
