import {
  ROOT,
  getConcurrentBubbles,
  isPredecessorHash,
  type Hash,
  type Link,
  type Resolver,
} from '@localfirst/crdx'
import { type Invitation } from 'invitation/index.js'
import { ADMIN } from 'role/index.js'
import { bySeniority, byDeviceSeniority } from 'team/bySeniority.js'
import {
  type AddMemberAction,
  type AddMemberRoleAction,
  type AdmitMemberAction,
  type MembershipRuleEnforcer,
  type RemoveDeviceAction,
  type RemoveMemberAction,
  type RemoveMemberRoleAction,
  type SignerUserMap,
  type TeamAction,
  type TeamContext,
  type TeamGraph,
  type TeamLink,
} from 'team/types.js'
import { arraysAreEqual } from 'util/arraysAreEqual.js'
import { isAdminOnlyAction } from './isAdminOnlyAction.js'

/**
 * This is a custom resolver, used to flatten a graph of team membership operations into a strictly
 * ordered sequence. It mostly applies "strong-remove" rules to resolve tricky situations that can
 * arise with concurrency: actions done while being removed, mutual removals, etc.
 *
 * Every rule here reasons about the *author* of a link, which we derive by mapping the signer named
 * in the link back to the member who registered it. That mapping is read straight off the graph's
 * registration links, so it's the same on every replica and doesn't depend on the order we happen
 * to be resolving.
 */
export const membershipResolver: Resolver<TeamAction, TeamContext> = graph => {
  const authors = getSignerUserMap(graph)
  const bubbles = getConcurrentBubbles(graph).map(hashes => hashes.map(hash => graph.links[hash]))
  const invalidLinks: TeamLink[] = []
  for (let bubble of bubbles) {
    for (const ruleName in membershipRules) {
      // Apply this rule to find any links that need to be invalidated
      const rule = membershipRules[ruleName]
      const invalidLinksByThisRule = rule(bubble, graph, authors)

      // Expand this list to include any links that depend on invalid links we've already found
      const alsoInvalid = invalidLinksByThisRule //
        // eslint-disable-next-line @typescript-eslint/no-loop-func
        .flatMap(link => findDependentLinks(bubble, link))

      invalidLinks.push(...invalidLinksByThisRule, ...alsoInvalid)

      bubble = bubble.filter(linkNotIn(invalidLinks))
    }
  }

  return {
    filter: linkNotIn(invalidLinks),
  }
}

/**
 * Maps each signer id in the graph to the member it acts for, using only the links that register
 * identities.
 *
 * This is order-independent: a registration is unique and immutable, and a signer's registration is
 * always a causal ancestor of anything it signs, so every replica builds the same map from the same
 * graph regardless of how it resolves concurrency. Servers map to themselves — a server's member
 * identity *is* its serverId.
 */
export const getSignerUserMap = (graph: TeamGraph): SignerUserMap => {
  const map: SignerUserMap = {}

  // Device invitations record the owner of the device they'll admit; that owner lives in the
  // INVITE_DEVICE link, so we collect those first.
  const invitationOwners: Record<string, string> = {}
  for (const link of Object.values(graph.links)) {
    if (link.body.type === 'INVITE_DEVICE') {
      const { invitation } = link.body.payload
      if (invitation.userId !== undefined) invitationOwners[invitation.id] = invitation.userId
    }
  }

  for (const link of Object.values(graph.links)) {
    const { type, payload } = link.body
    switch (type) {
      case ROOT: {
        map[payload.rootDevice.deviceId] = payload.rootMember.userId
        break
      }

      case 'ADD_MEMBER': {
        for (const device of payload.member.devices ?? []) {
          map[device.deviceId] = payload.member.userId
        }

        break
      }

      case 'ADMIT_MEMBER': {
        map[payload.claim.device.deviceId] = payload.claim.memberKeys.name
        break
      }

      case 'ADMIT_DEVICE': {
        const owner = invitationOwners[payload.id]
        if (owner !== undefined) map[payload.claim.device.deviceId] = owner
        break
      }

      case 'ADD_SERVER': {
        map[payload.server.serverId] = payload.server.serverId
        break
      }

      default: {
        break
      }
    }
  }

  return map
}

/**
 * Maps each signer id in the graph to the hash of the link that *registered* it: the ROOT for the
 * founding device, an ADD_MEMBER for a member's devices, an ADMIT_MEMBER/ADMIT_DEVICE for an
 * invited member's or device's registration, or an ADD_SERVER for a server.
 *
 * A signer's registration is the causal anchor that introduces its id into the graph. Every link a
 * signer produces must have that registration in its causal past — you can't sign as an identity
 * before the graph knew that identity existed. Unlike `getSignerUserMap` (which answers "who does
 * this id act for"), this answers "where was this id introduced", which is what lets us check
 * causal ancestry order-independently.
 */
export const getSignerRegistrationMap = (graph: TeamGraph): Record<string, Hash> => {
  const map: Record<string, Hash> = {}
  for (const link of Object.values(graph.links)) {
    const { type, payload } = link.body
    switch (type) {
      case ROOT: {
        map[payload.rootDevice.deviceId] = link.hash
        break
      }

      case 'ADD_MEMBER': {
        for (const device of payload.member.devices ?? []) {
          map[device.deviceId] = link.hash
        }

        break
      }

      case 'ADMIT_MEMBER':
      case 'ADMIT_DEVICE': {
        map[payload.claim.device.deviceId] = link.hash
        break
      }

      case 'ADD_SERVER': {
        map[payload.server.serverId] = link.hash
        break
      }

      default: {
        break
      }
    }
  }

  return map
}

/**
 * If we invalidate a link, we need to invalidate all links that depend on it. For example, if
 * someone joins the group but their invitation turns out to be invalid, then anything they do needs
 * to be invalidated, including if _they_ invited someone else — and so on recursively.
 */
const findDependentLinks = (bubble: TeamLink[], invalidLink: TeamLink): TeamLink[] => {
  const dependentLinks = [] as TeamLink[]
  const { type, payload } = invalidLink.body
  switch (type) {
    case 'INVITE_MEMBER':
    case 'INVITE_DEVICE': {
      // Invalidate ADMIT actions that used this invitation
      const { invitation } = payload
      dependentLinks.push(...bubble.filter(usesInvitation(invitation)))
      break
    }

    case 'ADD_MEMBER': {
      // Invalidate anything signed by the devices this link registered
      const deviceIds = (payload.member.devices ?? []).map(device => device.deviceId)
      dependentLinks.push(...bubble.filter(signedByAnyOf(deviceIds)))
      break
    }

    case 'ADMIT_MEMBER':
    case 'ADMIT_DEVICE': {
      // Invalidate anything signed by the device this admission registered. We match on the device
      // id rather than the owner's userId because that's what links are actually signed by — the
      // member may have other, still-valid devices.
      dependentLinks.push(...bubble.filter(signedByAnyOf([payload.claim.device.deviceId])))
      break
    }

    default: {
      break
    }
  }

  // Recursively find any links that depend on the ones we've just found to be invalid
  const alsoInvalid = dependentLinks.flatMap(l => findDependentLinks(bubble, l))
  return dependentLinks.concat(alsoInvalid)
}

const membershipRules: Record<string, MembershipRuleEnforcer> = {
  /**
   * RULE: a link may only be signed by an identity whose registration is in the link's causal past.
   *
   * A signer registered *concurrently* with (or after) a link it signed isn't yet known along that
   * link's own history, so the link was never causally authorized. Whether such a registration
   * happens to sort before or after the link is a topo-sort tiebreak, so resolving the signer
   * against `previousState` in `validate` would accept or reject the same link depending on the
   * order — and reject there means an uncaught throw that fails the *entire* graph load
   * (non-deterministic DoS). We settle it here instead, deterministically: every replica agrees on
   * causal ancestry, so every replica drops exactly the same links. A signer with no registration
   * anywhere in the graph is left alone — that's a genuine unknown signer, rejected downstream by
   * `resolveAuthor`.
   */
  requireSignerRegisteredInCausalPast(links, graph) {
    const registrations = getSignerRegistrationMap(graph)
    return links.filter(link => {
      const registrationHash = registrations[signerId(link)]
      // No registration in the graph at all: not our case (unknown signer, handled by resolveAuthor).
      if (registrationHash === undefined) return false
      // The founding device is registered by the very link it signs (the root); nothing precedes
      // the root, and a link isn't its own predecessor, so exempt that self-registration case.
      if (registrationHash === link.hash) return false
      // Otherwise the registration must be a causal ancestor of the link it authorizes.
      return !isPredecessorHash(graph, registrationHash, link.hash)
    })
  },

  // RULE: mutual and circular removals are resolved by seniority
  resolveMutualRemovals(links, graph, authors) {
    const removed = getRemovedAndDemotedMembers(links)
    const removers = getRemovalsAndDemotions(links).map(getAuthor(authors))

    // Is this a mutual/circular removal?
    const isCircularRemoval = removed.length > 0 && arraysAreEqual(removed, removers)
    if (!isCircularRemoval) {
      return []
    }

    // Find the least senior member and omit their actions
    return links.filter(authorIs(authors, leastSenior(graph, removers)))
  },

  /**
   * RULE: mutual and circular device removals are resolved by device seniority — the device that
   * was registered first wins, the same way the founding member wins among members.
   */
  resolveMutualDeviceRemovals(links, graph) {
    const removals = getDeviceRemovals(links)
    const removed = removals.map(link => link.body.payload.deviceId)
    const removers = removals.map(signerId)

    const isCircularRemoval = removed.length > 0 && arraysAreEqual(removed, removers)
    if (!isCircularRemoval) {
      return []
    }

    const leastSenior = removers.sort(byDeviceSeniority(graph)).pop()!
    return links.filter(link => signerId(link) === leastSenior)
  },

  // RULE: If A is removing C, B can't overcome this by concurrently removing C then adding C back
  cantAddBackRemovedMember(links) {
    const removedMembers = getRemovedAndDemotedMembers(links)
    return getAdditions(links).filter(link => removedMembers.includes(addedUserId(link)))
  },

  // RULE: If B is removed, anything they do concurrently is omitted
  cantDoAnythingWhenRemoved(links, _graph, authors) {
    const removedMembers = getRemovedMembers(links)
    return links.filter(authorIn(authors, removedMembers))
  },

  /**
   * RULE: If a device is removed, anything it signs concurrently is omitted — removal wins over
   * whatever the removed device was doing at the time. Retiring itself is the exception: that's the
   * removal, not something being overridden by it.
   */
  cantDoAnythingWhenDeviceRemoved(links) {
    const removedDevices = getDeviceRemovals(links).map(link => link.body.payload.deviceId)
    return links.filter(
      link => removedDevices.includes(signerId(link)) && !isSelfRemoval(link)
    )
  },

  // RULE: If B is demoted, any admin-only actions they do concurrently are omitted
  cantDoAdminActionsWhenDemoted(links, _graph, authors) {
    const demotedMembers = getDemotedMembers(links)
    const authorDemoted = authorIn(authors, demotedMembers)
    const isAdminOnly = (link: TeamLink) => isAdminOnlyAction(link.body)
    return links.filter(link => authorDemoted(link) && isAdminOnly(link))
  },
}

// Helpers

const leastSenior = (graph: TeamGraph, userIds: string[]) => userIds.sort(bySeniority(graph)).pop()!

const isAddAction = (link: TeamLink): link is AddActionLink =>
  ['ADD_MEMBER', 'ADD_MEMBER_ROLE', 'ADMIT_MEMBER'].includes(link.body.type)

const isRemovalAction = (link: TeamLink): boolean => link.body.type === 'REMOVE_MEMBER'

const getAdditions = (links: TeamLink[]) => links.filter(isAddAction)

const getRemovals = (links: TeamLink[]) => links.filter(isRemovalAction) as RemoveActionLink[]

const isDemotionAction = (link: TeamLink): boolean =>
  link.body.type === 'REMOVE_MEMBER_ROLE' && link.body.payload.roleName === ADMIN

const getDemotions = (links: TeamLink[]) => links.filter(isDemotionAction) as RemoveActionLink[]

const getRemovalsAndDemotions = (links: TeamLink[]) =>
  getRemovals(links).concat(getDemotions(links))

const getRemovedAndDemotedMembers = (links: TeamLink[]) =>
  getRemovalsAndDemotions(links).map(getTarget)

const getRemovedMembers = (links: TeamLink[]) => getRemovals(links).map(getTarget)
const getDemotedMembers = (links: TeamLink[]) => getDemotions(links).map(getTarget)

const getTarget = (link: RemoveActionLink): string => link.body.payload.userId

/** A device retiring itself isn't a conflict between two devices, so it's excluded from the
 * mutual-removal and removal-wins rules. */
const isSelfRemoval = (link: TeamLink) =>
  link.body.type === 'REMOVE_DEVICE' && link.body.payload.deviceId === signerId(link)

const getDeviceRemovals = (links: TeamLink[]) =>
  links.filter(link => link.body.type === 'REMOVE_DEVICE' && !isSelfRemoval(link)) as RemoveDeviceLink[]

const signerId = (link: TeamLink): string => link.body.signer.id

/** The member a link is attributed to: whoever registered the signer that signed it. */
const getAuthor = (authors: SignerUserMap) => (link: TeamLink) => authors[signerId(link)]

const authorIs = (authors: SignerUserMap, author: string) => (link: TeamLink) =>
  getAuthor(authors)(link) === author

const authorIn =
  (authors: SignerUserMap, excludeList: string[]) =>
  (link: TeamLink): boolean =>
    excludeList.includes(getAuthor(authors)(link))

const signedByAnyOf = (signerIds: string[]) => (link: TeamLink) =>
  signerIds.includes(signerId(link))

const addedUserId = (link: AddActionLink): string => {
  switch (link.body.type) {
    case 'ADD_MEMBER': {
      const addAction = link.body
      return addAction.payload.member.userId
    }

    case 'ADD_MEMBER_ROLE': {
      const addAction = link.body
      return addAction.payload.userId
    }

    case 'ADMIT_MEMBER': {
      const addAction = link.body
      return addAction.payload.claim.memberKeys.name
    }
  }
}

const linkNotIn =
  (excludeList: TeamLink[]) =>
  (link: TeamLink): boolean =>
    !excludeList.includes(link)

const usesInvitation = (invitation: Invitation) => (l: TeamLink) =>
  (l.body.type === 'ADMIT_MEMBER' || l.body.type === 'ADMIT_DEVICE') &&
  l.body.payload.id === invitation.id

type RemoveActionLink = Link<RemoveMemberAction | RemoveMemberRoleAction, TeamContext>
type RemoveDeviceLink = Link<RemoveDeviceAction, TeamContext>
type AddActionLink = Link<AddMemberAction | AddMemberRoleAction | AdmitMemberAction, TeamContext>
