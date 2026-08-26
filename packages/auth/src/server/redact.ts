import { redactKeys } from '@localfirst/crdx'
import type { Server, ServerWithSecrets } from './types.js'

/** Returns the public record of a server — what gets registered on the team graph. */
export const redactServer = (server: ServerWithSecrets): Server => ({
  ...server,
  identityKeys: redactKeys(server.identityKeys),
  keys: redactKeys(server.keys),
})
