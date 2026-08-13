import type { KeysetWithSecrets } from '@localfirst/crdx'
import { assert } from '@localfirst/shared'
import type { ConnectionMessage } from 'connection/message.js'
import { castServer } from 'server/castServer.js'
import { syncMessageSummary } from 'util/testing/messageSummary.js'
import { type ConnectionContext, type Context, type ServerContext, isServerContext } from './types.js'

// HELPERS
// FOR DEBUGGING
export const messageSummary = (message: ConnectionMessage) =>
  message.type === 'SYNC'
    ? `SYNC ${syncMessageSummary(message.payload)}`
    : // @ts-expect-error utility function don't worry about it
      `${message.type} ${message.payload?.head?.slice(0, 5) || message.payload?.message || ''}`
const isString = (state: any): state is string => typeof state === 'string'
// ignore coverage
export const stateSummary = (state: any): string =>
  isString(state)
    ? state
    : Object.keys(state)
        .map(key => `${key}:${stateSummary(state[key])}`)
        .filter(s => s.length)
        .join(',')

/**
 * A server takes part in the team's key hierarchy as if it were a member — lockboxes are addressed
 * to its rotatable keys — so we give it a member projection up front and the rest of the protocol
 * doesn't have to care. It gets no device: a server is not a device, and it authenticates and
 * signs with its own immutable identity keys (see `ourSigningKeys`).
 */
export const extendServerContext = (context: ServerContext) => ({
  ...context,
  user: castServer.toUser(context.server),
})

/**
 * The keys that open lockboxes addressed to us, and that we negotiate the session key with: our
 * device's keys, or a server's rotatable keys.
 */
export const ourLockboxKeys = (context: ConnectionContext): KeysetWithSecrets => {
  if (isServerContext(context)) return context.server.keys
  assert(context.device, 'A member connection needs a device')
  return context.device.keys
}

/**
 * The keys we answer an identity challenge with. These are the keys the team has registered as our
 * signing identity: a device's keys, or a server's identity keys (which never rotate, so a
 * re-keyed server can still authenticate).
 */
export const ourSigningKeys = (context: ConnectionContext): KeysetWithSecrets => {
  if (isServerContext(context)) return context.server.identityKeys
  assert(context.device, 'A member connection needs a device')
  return context.device.keys
}

export const getUserName = (context: Context) => {
  if ('server' in context) return context.server.host
  if ('userName' in context) return context.userName
  if ('user' in context) return context.user.userName
  return ''
}
