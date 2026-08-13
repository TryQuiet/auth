import { ROOT, isPredecessor } from '@localfirst/crdx'
import { assert } from '@localfirst/shared'
import { type TeamGraph, type TeamLink } from 'team/types.js'

/**
 * Sorts members by seniority, most senior first. Seniority is the order in which the graph
 * registered them, which every replica reads the same way; it's how mutual removals get a
 * deterministic winner.
 */
export const bySeniority = (graph: TeamGraph) => (a: string, b: string) => {
  // If one of these created the team, they win
  if (isFounder(graph, a)) return -1
  if (isFounder(graph, b)) return 1

  const [addedA, addedB] = [a, b].map(userId => linkThatAddedMember(graph, userId))

  // if A was added first, A comes first in the sort
  // ignore coverage
  return isPredecessor(graph, addedA, addedB) ? -1 : 1
}

/** Sorts devices by seniority, most senior first — same rule as members, applied to registrations. */
export const byDeviceSeniority = (graph: TeamGraph) => (a: string, b: string) => {
  if (isFoundingDevice(graph, a)) return -1
  if (isFoundingDevice(graph, b)) return 1

  const [addedA, addedB] = [a, b].map(deviceId => linkThatAddedDevice(graph, deviceId))

  // ignore coverage
  return isPredecessor(graph, addedA, addedB) ? -1 : 1
}

const rootPayload = (graph: TeamGraph) => {
  const rootLink = graph.links[graph.root]
  assert(rootLink.body.type === ROOT, 'The graph root must be a ROOT link')
  return rootLink.body.payload
}

const isFounder = (graph: TeamGraph, userId: string) => rootPayload(graph).rootMember.userId === userId

const isFoundingDevice = (graph: TeamGraph, deviceId: string) =>
  rootPayload(graph).rootDevice.deviceId === deviceId

const linkThatAddedMember = (graph: TeamGraph, userId: string) => {
  const addedMember = (link: TeamLink) =>
    (link.body.type === 'ADD_MEMBER' && link.body.payload.member.userId === userId) ||
    (link.body.type === 'ADMIT_MEMBER' && link.body.payload.claim.memberKeys.name === userId)
  const result = Object.values(graph.links).find(addedMember)
  assert(result, `Could not find link that added member ${userId}`)
  return result
}

const linkThatAddedDevice = (graph: TeamGraph, deviceId: string) => {
  const addedDevice = (link: TeamLink) => {
    const { type, payload } = link.body
    if (type === 'ADD_MEMBER') {
      return (payload.member.devices ?? []).some(device => device.deviceId === deviceId)
    }

    if (type === 'ADMIT_MEMBER' || type === 'ADMIT_DEVICE') {
      return payload.claim.device.deviceId === deviceId
    }

    return false
  }

  const result = Object.values(graph.links).find(addedDevice)
  assert(result, `Could not find link that added device ${deviceId}`)
  return result
}
