import { type Keyset, type KeysetWithSecrets } from '@localfirst/crdx'

/**
 * A server has two keysets, because it plays two roles on a team:
 *
 * - `identityKeys` are its **signing identity**: they sign the links it authors and the challenges
 *   it answers when connecting. They are immutable, which is what makes `serverId` — their
 *   fingerprint — a permanent, self-certifying name for the server.
 * - `keys` are its **member keys**: lockboxes are addressed to them, so they have to rotate (via
 *   `CHANGE_SERVER_KEYS`) whenever the server needs to be re-keyed.
 *
 * `host` is a routing and display label. It can change, it isn't unique in any cryptographic
 * sense, and nothing may authenticate or authorize a server by it.
 */
export type ServerWithSecrets = {
  host: Host
  serverId: string
  identityKeys: KeysetWithSecrets
  keys: KeysetWithSecrets
}

export type Server = {
  /** Routing/display label only — never an identity. */
  host: Host

  /** Self-certifying identifier: the fingerprint of the server's public identity signature key
   * (`signerIdFromKeys(identityKeys)`), and also `identityKeys.name`. */
  serverId: string

  /** Immutable signing identity. Authors links and answers connection challenges. */
  identityKeys: Keyset

  /** Rotatable keys. Lockboxes are addressed to these; they never author links. */
  keys: Keyset
}

/** The hostname, possibly including a port number; e.g. `example.com`, `localhost:8080`, `188.26.221.135`  */
export type Host = string
