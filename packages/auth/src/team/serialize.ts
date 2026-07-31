import {
  decryptGraph,
  getChildMap,
  type EncryptedGraph,
  type Keyring,
  type LinkMap,
} from '@localfirst/crdx'
import { type TeamGraph } from './types.js'
import { pack, unpack } from 'msgpackr'

export const EMPTY: LinkMap = {}

export const serializeTeamGraph = (graph: TeamGraph) => {
  const childMap = getChildMap(graph)

  // Leave out the unencrypted `links` element
  const { encryptedLinks, head, root } = graph
  const encryptedGraph = { encryptedLinks, childMap, head, root }

  const serialized = pack(encryptedGraph)
  return toUint8Array(serialized)
}

export const deserializeTeamGraph = (serialized: Uint8Array, keys: Keyring): TeamGraph => {
  const encryptedGraph = unpack(serialized) as EncryptedGraph
  return decryptGraph({ encryptedGraph, keys })
}

/**
 * Loads a serialized graph or authenticates an in-memory graph for public use. Serialized sources
 * are decrypted normally; in-memory plaintext `links` are ignored and reconstructed from encrypted
 * links before validation or reduction.
 */
export const maybeDeserialize = (
  source: Uint8Array | TeamGraph,
  teamKeyring: Keyring
): TeamGraph => {
  if (!isGraph(source)) {
    return deserializeTeamGraph(source, teamKeyring)
  }

  // A supplied Graph may contain attacker-controlled plaintext `links`. Reconstruct every link
  // from its authenticated ciphertext before exposing it to validation or reduction.
  return decryptGraph({
    encryptedGraph: { ...source, childMap: getChildMap(source) },
    keys: teamKeyring,
  })
}

const isGraph = (source: Uint8Array | TeamGraph): source is TeamGraph =>
  source?.hasOwnProperty('root')

// buffer to uint8array
const toUint8Array = (buf: globalThis.Buffer) =>
  new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
