import { NOLOG, wrap } from '../helpers'
import { type CommandFn } from '../types.js'

export const SECOND = 1
export const MINUTE = 60 * SECOND
export const HOUR = 60 * MINUTE
export const DAY = 24 * HOUR
export const WEEK = 7 * DAY

export type InviteOptions = {
  expiration?: typeof SECOND | typeof MINUTE
}

export const invite: CommandFn = (subject, options: InviteOptions = {}) => {
  const { expiration = MINUTE } = options
  const s = () => wrap(subject)
  // click invite button
  s().findByText('Invite members', NOLOG).click(NOLOG)

  // set expiration
  s()
    .findByLabelText('When does this invitation code expire?', NOLOG)
    .select(expiration.toString(), NOLOG)

  // press invite button
  s().findByText('Invite', NOLOG).click(NOLOG)

  // capture invitation code
  return s()
    .get('pre.InvitationCode', NOLOG)
    .then(pre => {
      s().findByText('Copy', NOLOG).click(NOLOG)
      const code = wrap(pre).invoke(NOLOG, 'text')
      return code
    })
}
