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

export const maybeDeserialize = (
  source: Uint8Array | TeamGraph,
  teamKeyring: Keyring
): TeamGraph => {
  if (!isGraph(source)) return deserializeTeamGraph(source, teamKeyring)

  // An object-form graph is no more trustworthy than a serialized one — it may have come from a
  // peer, and its `links` may say anything. The hashes commit to the ciphertext, so we rebuild the
  // plaintext from that rather than believing what we were handed.
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
