import { ROOT, type Keyset } from '@localfirst/crdx'
import { isBase58KeyOfLength } from '@localfirst/crypto'
import { type Logger } from '@localfirst/shared'
import {
  isKeyManifest,
  isRecipientManifest,
  type Lockbox,
  type RecipientManifest,
} from 'lockbox/index.js'
import { ADMIN } from 'role/index.js'
import { KeyType } from 'util/index.js'
import * as select from './selectors/index.js'
import {
  isLockboxCarrierAction,
  SignerKind,
  type LockboxCarrierAction,
  type TeamLink,
  type TeamState,
} from './types.js'

/**
 * Decides which of a link's lockboxes may be applied to the team's state.
 *
 * A lockbox is a delivery of a capability. It is therefore accepted only when the action that
 * carries it has a declared delivery purpose. This keeps lockboxes from becoming an ambient
 * authority channel: a MESSAGE, metadata update, or copied link cannot silently grant access to a
 * key merely by adding a `lockboxes` property.
 *
 * A link that introduces a *higher* generation than the team has for a TEAM or ROLE scope is a
 * re-key, and must satisfy all of:
 *
 *   (a) the author is an admin. Holding a shared key permits reading and exact redistribution, but
 *       it does not grant authority to replace that key with a new generation.
 *   (b) it increments the current generation by exactly one — no gaps, no leapfrogging to a number
 *       that would outrank every honest rotation forever.
 *   (c) it reaches every holder implied by membership and role state, all under one key: no silent
 *       exclusions, no handing different holders divergent keysets. Lockbox recipients are delivery
 *       addresses, never the authorization registry.
 *
 * WHY THIS DROPS RATHER THAN REJECTS. A link whose lockboxes fail these checks is not rejected; the
 * offending lockboxes are simply not collected, and the link's action applies as usual. That is
 * deliberate, and it is the difference between this and a validator:
 *
 *   - Validators throw, and a throw here is unrecoverable — `getTeamState` re-reduces the whole
 *     graph on every cold load, so one link that can't be reduced bricks the team permanently
 *     (#58). Making that outcome depend on *concurrent* state is how you poison a graph (#63).
 *   - And (c) does depend on concurrent state: the holder set grows whenever anyone is added to the
 *     scope. An admission or a role-add that merges in *before* an honest re-key makes that re-key
 *     look like it excludes someone. `lockboxRotationConcurrency.test.ts` is exactly that merge —
 *     two honest admins, no attacker — and as a throwing validator it kills the graph.
 *
 * Dropping converges instead: it's a pure function of the resolved sequence, so every replica
 * computes the same state, and the scope simply stays on the generation it was already on. Nobody
 * is locked out by it either, because lockboxes are append-only — the generations a member could
 * already reach stay reachable, and a re-key that gets dropped can just be re-issued from current
 * state. Against the attack it is *stronger* than throwing: Eve can neither rotate the key nor
 * brick the graph by publishing a link nobody can reduce.
 */
export const authorizedLockboxes = (
  previousState: TeamState,
  projectedState: TeamState,
  link: TeamLink,
  lockboxes: unknown,
  logger: Logger
): Lockbox[] => {
  if (!isLockboxCarrierAction(link.body)) {
    logger.warn(
      `Dropping lockboxes from ${link.body.type} link ${link.hash}: action cannot carry key deliveries`
    )
    return []
  }

  if (!Array.isArray(lockboxes)) {
    logger.warn(`Dropping malformed lockbox payload from link ${link.hash}: expected an array`)
    return []
  }

  const dropped = new Set<Lockbox>()
  const drop = (rejects: Lockbox[], scope: KeyScope, reason: string) => {
    if (rejects.length === 0) return
    for (const lockbox of rejects) dropped.add(lockbox)
    logger.warn(
      `Dropping ${rejects.length} lockbox(es) for ${scopeId(scope)} from link ${link.hash}: ${reason}`
    )
  }

  // A manifest is the public authorization boundary for an encrypted keyset. Old manifests and
  // malformed commitments are unusable, but they must not make the link carrying them unusable.
  // Remember the coordinates of malformed manifests when possible: if this link is trying to
  // establish a new distribution batch, one malformed recipient makes that whole batch
  // uncommitted rather than allowing the remaining recipients to establish it partially.
  const malformedBatches = new Set<string>()
  let hasUnidentifiedMalformedLockbox = false
  const validLockboxes: Lockbox[] = []
  for (const candidate of lockboxes as unknown[]) {
    const contents = isRecord(candidate) ? candidate.contents : undefined
    if (isAuthorizationLockbox(candidate)) {
      validLockboxes.push(candidate)
      continue
    }

    const identity = keyIdentity(contents)
    if (identity === undefined) {
      hasUnidentifiedMalformedLockbox = true
    } else {
      malformedBatches.add(keyIdentityId(identity))
    }

    logger.warn(`Dropping malformed lockbox from link ${link.hash}: invalid lockbox structure`)
  }

  // Bind every scope/generation pair that has already reached state to the first valid commitment
  // established for it. This applies to historical and identity-owned keys as well as the current
  // generation of TEAM/ROLE keys. The advertised encryption public key remains inspectable, but
  // is deliberately not used as keyset identity: the commitment covers both keypairs, the
  // symmetric secret, and all metadata.
  const established = establishedCommitments(previousState.lockboxes)
  const batches = groupByKeyIdentity(validLockboxes)

  for (const [id, batch] of batches) {
    const scope = scopeOf(batch[0])
    const establishedCommitment = established.get(id)

    if (establishedCommitment !== undefined) {
      drop(
        batch.filter(({ contents }) => contents.commitment !== establishedCommitment),
        scope,
        `generation ${batch[0].contents.generation} is already bound to another keyset commitment`
      )
      continue
    }

    // A new generation is established by the batch as a whole. It must not be possible for one
    // link to give different recipients different keysets under the same generation number, or to
    // establish a partial batch after one recipient's manifest was discarded as malformed.
    const commitments = new Set(batch.map(({ contents }) => contents.commitment))
    if (hasUnidentifiedMalformedLockbox || malformedBatches.has(id) || commitments.size !== 1) {
      drop(batch, scope, `generation ${batch[0].contents.generation} is not one committed keyset`)
      continue
    }

    // USER and SERVER generations are public identity records before they are lockbox contents.
    // Do not let an unrelated link bind an unseen generation first and make the identity owner's
    // later, legitimate distribution look conflicting. Registration/key-change links may establish
    // exactly the public keyset they record. The one post-registration exception is a member's own
    // device-signed USER distribution: invitation admission cannot carry the user's secret keys,
    // so `Team.join` must box them to that already-registered device in a follow-up link.
    if (
      isIdentityScope(scope.type) &&
      !mayEstablishIdentityKeyset(previousState, link, batch[0].contents)
    ) {
      drop(
        batch,
        scope,
        `generation ${batch[0].contents.generation} is not established by its identity owner`
      )
    }
  }

  // Structural validity says only that a lockbox is well formed. The action policy below says
  // what it is allowed to deliver, to whom, and whether it may establish a new generation.
  for (const lockbox of validLockboxes) {
    if (dropped.has(lockbox)) continue
    const reason = actionPolicyReason(previousState, projectedState, link, lockbox)
    if (reason !== undefined) drop([lockbox], scopeOf(lockbox), reason)
  }

  // The shared scopes this link's surviving lockboxes distribute keys for. Commitment binding
  // above applies to every key type; the authorization and holder-set rules below are specific to
  // shared TEAM/ROLE rotations.
  const scopes = new Map<string, KeyScope>()
  for (const lockbox of validLockboxes) {
    if (dropped.has(lockbox)) continue
    const { contents } = lockbox
    if (!isKeyManifest(contents) || !isSharedScope(contents.type)) continue
    scopes.set(scopeKey(contents), { type: contents.type, name: contents.name })
  }

  if (scopes.size === 0) {
    return validLockboxes.filter(lockbox => !dropped.has(lockbox))
  }

  const authorizationState = {
    ...previousState,
    lockboxes: previousState.lockboxes.filter(isAuthorizationLockbox),
  }
  for (const scope of scopes.values()) {
    const prior = select.lockboxesInScope(authorizationState, scope)
    const inScope = validLockboxes.filter(
      lockbox =>
        !dropped.has(lockbox) &&
        isKeyManifest(lockbox.contents) &&
        scopesMatch(lockbox.contents, scope)
    )

    if (prior.length === 0) {
      if (!actionCreatesSharedScope(link.body, scope)) {
        drop(inScope, scope, 'action does not establish this shared scope')
        continue
      }

      if (inScope.some(({ contents }) => contents.generation !== 0)) {
        drop(inScope, scope, 'new shared scopes must begin at generation 0')
        continue
      }

      const expected = expectedRecipientsForScope(
        projectedState,
        previousState,
        link,
        scope,
        validLockboxes.filter(lockbox => !dropped.has(lockbox))
      )
      if (expected === undefined) {
        drop(inScope, scope, 'administrator access cannot be carried into this rotation plan')
        continue
      }
      if (!reachesExactly(inScope, expected)) {
        drop(
          inScope,
          scope,
          `initial distribution does not reach exactly [${recipientList(expected)}]`
        )
      }
      continue
    }

    const currentGeneration = prior[0].contents.generation
    const rekey = inScope.filter(({ contents }) => contents.generation > currentGeneration)

    // Same-generation deliveries are constrained by actionPolicyReason: a joiner may receive
    // historical TEAM generations and a new role holder may receive that role's existing keys, but
    // arbitrary actions cannot redistribute a current key.
    if (rekey.length === 0) continue

    // Only a declared rotation transition, authored by an admin, can introduce a shared generation.
    const author = actingMemberId(previousState, link)
    const authorIsAdmin = author !== undefined && select.memberIsAdmin(previousState, author)
    if (!isRotationAction(link.body) || !authorIsAdmin) {
      drop(rekey, scope, `'${author ?? 'unknown signer'}' is not an admin`)
      continue
    }

    // (b) A re-key advances the generation by one. Anything further ahead would outrank every
    // honest rotation from here on, and would leave holes in the keyring that callers index by
    // generation.
    const nextGeneration = currentGeneration + 1
    drop(
      rekey.filter(({ contents }) => contents.generation !== nextGeneration),
      scope,
      `re-key must advance generation ${currentGeneration} by one`
    )
    const next = rekey.filter(({ contents }) => contents.generation === nextGeneration)
    if (next.length === 0) continue

    // The post-action state determines who is entitled to the replacement. Delivery addresses may
    // change during an identity rotation, but those addresses do not create new holders.
    const expected = expectedRecipientsForScope(
      projectedState,
      previousState,
      link,
      scope,
      validLockboxes.filter(lockbox => !dropped.has(lockbox))
    )
    if (expected === undefined) {
      drop(next, scope, 'administrator access cannot be carried into this rotation plan')
      continue
    }
    if (!reachesExactly(next, expected)) {
      drop(next, scope, `re-key does not reach exactly [${recipientList(expected)}]`)
    }
  }

  return validLockboxes.filter(lockbox => !dropped.has(lockbox))
}

/** Returns a reason when a structurally valid lockbox is outside its action's delivery contract. */
const actionPolicyReason = (
  previousState: TeamState,
  projectedState: TeamState,
  link: TeamLink,
  lockbox: Lockbox
): string | undefined => {
  const action = link.body
  if (!isLockboxCarrierAction(action)) return 'action cannot carry key deliveries'

  const { contents, recipient } = lockbox
  switch (action.type) {
    case ROOT: {
      if (contents.generation !== 0) return 'ROOT may only establish generation-zero keys'
      if (isTeamScope(contents) && recipientMatchesKeys(recipient, action.payload.rootMember.keys))
        return undefined
      if (
        isRoleScope(contents, ADMIN) &&
        recipientMatchesKeys(recipient, action.payload.rootMember.keys)
      ) {
        return undefined
      }
      if (
        keysetMatchesManifest(action.payload.rootMember.keys, contents) &&
        recipientMatchesKeys(recipient, action.payload.rootDevice.keys)
      ) {
        return undefined
      }
      return 'ROOT may deliver only TEAM, ADMIN, and founding USER keys to the founding identity'
    }

    case 'ADD_MEMBER': {
      const { member, roles = [] } = action.payload
      if (
        keysetMatchesManifest(member.keys, contents) &&
        (member.devices ?? []).some(device => recipientMatchesKeys(recipient, device.keys))
      ) {
        return undefined
      }

      const assignedRoles = new Set(roles)
      const isPermittedSharedKey =
        isTeamScope(contents) ||
        (contents.type === KeyType.ROLE && assignedRoles.has(contents.name))
      if (
        isPermittedSharedKey &&
        knownContents(previousState, contents) &&
        recipientMatchesKeys(recipient, member.keys)
      ) {
        return undefined
      }
      return 'ADD_MEMBER may deliver existing TEAM or assigned ROLE keys to the added member'
    }

    case 'ADMIT_MEMBER': {
      if (
        isTeamScope(contents) &&
        knownContents(previousState, contents) &&
        recipientMatchesKeys(recipient, action.payload.claim.memberKeys)
      ) {
        return undefined
      }
      return 'ADMIT_MEMBER may deliver existing TEAM generations only to the admitted member'
    }

    case 'ADD_ROLE': {
      if (
        isRoleScope(contents, action.payload.roleName) &&
        contents.generation === 0 &&
        recipientIsExpectedForScope(projectedState, previousState, link, contents, [lockbox])
      ) {
        return undefined
      }
      return 'ADD_ROLE may establish generation-zero keys only for the role being added'
    }

    case 'ADD_MEMBER_ROLE': {
      const member = projectedState.members.find(
        candidate => candidate.userId === action.payload.userId
      )
      if (
        member !== undefined &&
        isRoleScope(contents, action.payload.roleName) &&
        knownContents(previousState, contents) &&
        recipientMatchesKeys(recipient, member.keys)
      ) {
        return undefined
      }
      return 'ADD_MEMBER_ROLE may deliver existing keys of that role only to the assigned member'
    }

    case 'INVITE_DEVICE': {
      const { invitation } = action.payload
      const owner =
        invitation.userId === undefined
          ? undefined
          : previousState.members.find(member => member.userId === invitation.userId)
      if (
        owner !== undefined &&
        keysetMatchesManifest(owner.keys, contents) &&
        recipient.type === KeyType.EPHEMERAL &&
        recipient.name === KeyType.EPHEMERAL &&
        recipient.generation === 0 &&
        recipient.publicKey === invitation.encryptionPublicKey
      ) {
        return undefined
      }
      return 'INVITE_DEVICE may deliver its owner’s USER key only to that invitation starter'
    }

    case 'PUBLISH_USER_KEYS_TO_DEVICE': {
      const ownerId = actingMemberId(previousState, link)
      const owner =
        ownerId === undefined
          ? undefined
          : previousState.members.find(member => member.userId === ownerId)
      const device = owner?.devices?.find(
        candidate => candidate.deviceId === action.payload.deviceId
      )
      if (
        link.body.signer.kind === SignerKind.DEVICE &&
        link.body.signer.id === action.payload.deviceId &&
        owner !== undefined &&
        device !== undefined &&
        keysetMatchesManifest(owner.keys, contents) &&
        recipientMatchesKeys(recipient, device.keys)
      ) {
        return undefined
      }
      return 'PUBLISH_USER_KEYS_TO_DEVICE may deliver the author’s USER key only to its registered device'
    }

    case 'ADD_SERVER': {
      if (
        isTeamScope(contents) &&
        knownContents(previousState, contents) &&
        recipientMatchesKeys(recipient, action.payload.server.keys)
      ) {
        return undefined
      }
      return 'ADD_SERVER may deliver existing TEAM keys only to the added server'
    }

    case 'REMOVE_SERVER': {
      if (!isTeamScope(contents)) return 'REMOVE_SERVER may rotate only TEAM keys'
      return sharedRotationReason(previousState, contents)
    }

    case 'REMOVE_MEMBER': {
      if (!memberCanHoldSharedScope(previousState, action.payload.userId, contents)) {
        return 'REMOVE_MEMBER may rotate only keys the removed member was authorized to hold'
      }
      return sharedRotationReason(previousState, contents)
    }

    case 'REMOVE_MEMBER_ROLE': {
      const removesAdminAccess = action.payload.roleName === ADMIN && contents.type === KeyType.ROLE
      if (!removesAdminAccess && !isRoleScope(contents, action.payload.roleName)) {
        return 'REMOVE_MEMBER_ROLE may rotate only the removed role'
      }
      return sharedRotationReason(previousState, contents)
    }

    case 'REMOVE_DEVICE': {
      const owner = identityRotationOwner(previousState, link)
      if (
        isSharedScope(contents.type) &&
        !memberCanHoldSharedScope(previousState, owner, contents)
      ) {
        return 'REMOVE_DEVICE may rotate only keys its owner was authorized to hold'
      }
      const sharedReason = sharedRotationReason(previousState, contents)
      return sharedReason === undefined
        ? undefined
        : identityRotationReason(previousState, projectedState, link, lockbox)
    }

    case 'CHANGE_MEMBER_KEYS': {
      if (
        isSharedScope(contents.type) &&
        !memberCanHoldSharedScope(previousState, action.payload.keys.name, contents)
      ) {
        return 'CHANGE_MEMBER_KEYS may rotate only keys that member was authorized to hold'
      }
      const sharedReason = sharedRotationReason(previousState, contents)
      if (sharedReason === undefined) return undefined
      if (
        keysetMatchesManifest(action.payload.keys, contents) &&
        recipientIsActiveDeviceOf(projectedState, action.payload.keys.name, recipient)
      ) {
        return undefined
      }
      return 'CHANGE_MEMBER_KEYS may deliver its declared USER key only to the member’s active devices'
    }

    case 'CHANGE_SERVER_KEYS': {
      if (isSharedScope(contents.type) && !isTeamScope(contents)) {
        return 'CHANGE_SERVER_KEYS may rotate only TEAM keys'
      }
      const sharedReason = sharedRotationReason(previousState, contents)
      if (sharedReason === undefined) return undefined
      if (
        keysetMatchesManifest(action.payload.keys, contents) &&
        recipientMatchesKeys(recipient, action.payload.keys)
      ) {
        return undefined
      }
      return 'CHANGE_SERVER_KEYS may deliver only its declared SERVER key or an authorized shared rotation'
    }

    case 'ROTATE_KEYS': {
      const owner = actingMemberId(previousState, link)
      if (
        isSharedScope(contents.type) &&
        !memberCanHoldSharedScope(previousState, owner, contents)
      ) {
        return 'ROTATE_KEYS may rotate only keys its author is authorized to hold'
      }
      const sharedReason = sharedRotationReason(previousState, contents)
      return sharedReason === undefined
        ? undefined
        : identityRotationReason(previousState, projectedState, link, lockbox)
    }

    default: {
      return 'action cannot carry key deliveries'
    }
  }
}

const sharedRotationReason = (
  previousState: TeamState,
  contents: Lockbox['contents']
): string | undefined => {
  if (!isSharedScope(contents.type)) return 'action may not deliver this key type'
  const currentGeneration = currentSharedGeneration(previousState, contents)
  if (currentGeneration === undefined)
    return 'rotation references a shared scope with no established key'
  if (contents.generation !== currentGeneration + 1) {
    return `rotation must advance generation ${currentGeneration} by one`
  }
  return undefined
}

const identityRotationReason = (
  previousState: TeamState,
  projectedState: TeamState,
  link: TeamLink,
  lockbox: Lockbox
): string | undefined => {
  const owner = identityRotationOwner(previousState, link)
  const { contents, recipient } = lockbox
  if (
    owner !== undefined &&
    contents.type === KeyType.USER &&
    contents.name === owner &&
    contents.generation === latestIdentityGeneration(previousState, KeyType.USER, owner) + 1 &&
    recipientIsActiveDeviceOf(projectedState, owner, recipient)
  ) {
    return undefined
  }
  return 'identity rotation may deliver only the affected USER key to that user’s active devices'
}

const memberCanHoldSharedScope = (
  state: TeamState,
  userId: string | undefined,
  scope: KeyScope
) => {
  if (userId === undefined) return false
  if (isTeamScope(scope)) return true
  if (scope.type !== KeyType.ROLE) return false

  const member = state.members.find(candidate => candidate.userId === userId)
  return member !== undefined && (member.roles.includes(scope.name) || member.roles.includes(ADMIN))
}

const actionCreatesSharedScope = (action: LockboxCarrierAction, scope: KeyScope) =>
  (action.type === ROOT && (isTeamScope(scope) || isRoleScope(scope, ADMIN))) ||
  (action.type === 'ADD_ROLE' && isRoleScope(scope, action.payload.roleName))

const isRotationAction = (action: LockboxCarrierAction) =>
  action.type === 'REMOVE_MEMBER' ||
  action.type === 'REMOVE_MEMBER_ROLE' ||
  action.type === 'REMOVE_DEVICE' ||
  action.type === 'REMOVE_SERVER' ||
  action.type === 'CHANGE_MEMBER_KEYS' ||
  action.type === 'CHANGE_SERVER_KEYS' ||
  action.type === 'ROTATE_KEYS'

const expectedRecipientsForScope = (
  projectedState: TeamState,
  previousState: TeamState,
  link: TeamLink,
  scope: KeyScope,
  next: Lockbox[]
): RecipientManifest[] | undefined => {
  if (isTeamScope(scope)) {
    const holders = [
      ...projectedState.members.map(member => member.keys),
      ...projectedState.servers.map(server => server.keys),
    ]
    return uniqueRecipients(
      holders.map(
        keys =>
          replacementRecipientForIdentityRotation(previousState, link, keys, next) ??
          recipientForKeys(keys)
      )
    )
  }

  const roleMembers = projectedState.members
    .filter(member => member.roles.includes(scope.name))
    .map(member => member.keys)
  if (scope.name === ADMIN) {
    return uniqueRecipients(
      roleMembers.map(
        keys =>
          replacementRecipientForIdentityRotation(previousState, link, keys, next) ??
          recipientForKeys(keys)
      )
    )
  }

  const recipients = roleMembers.map(
    keys =>
      replacementRecipientForIdentityRotation(previousState, link, keys, next) ??
      recipientForKeys(keys)
  )
  const adminRecipient = adminAccessRecipient(previousState, projectedState, link, next)
  if (adminRecipient === undefined) return undefined
  recipients.push(adminRecipient)
  return uniqueRecipients(recipients)
}

/** The ADMIN role key is the explicit administrator-access delivery address for other roles. */
const adminAccessRecipient = (
  previousState: TeamState,
  projectedState: TeamState,
  link: TeamLink,
  lockboxes: Lockbox[]
): RecipientManifest | undefined => {
  const authorizationState = {
    ...previousState,
    lockboxes: previousState.lockboxes.filter(isAuthorizationLockbox),
  }
  const prior = select.lockboxesInScope(authorizationState, { type: KeyType.ROLE, name: ADMIN })[0]
  const currentGeneration = prior?.contents.generation
  if (currentGeneration === undefined) return undefined

  const replacements = lockboxes.filter(
    ({ contents }) => isRoleScope(contents, ADMIN) && contents.generation === currentGeneration + 1
  )

  // A new non-ADMIN role key is normally addressed to the current ADMIN role key. If this action
  // also changes administrator access, it must first supply a complete replacement ADMIN plan;
  // otherwise an old administrator could remain the delivery address for a fresh role generation.
  if (replacements.length === 0) {
    if (actionRequiresAdminRotation(previousState, link)) return undefined
    return recipientForContents(prior.contents)
  }

  const expectedAdmins = uniqueRecipients(
    projectedState.members
      .filter(member => member.roles.includes(ADMIN))
      .map(
        member =>
          replacementRecipientForIdentityRotation(previousState, link, member.keys, lockboxes) ??
          recipientForKeys(member.keys)
      )
  )
  if (!reachesExactly(replacements, expectedAdmins)) return undefined

  return recipientForContents(replacements[0].contents)
}

/** Whether this transition invalidates the current ADMIN key's delivery authority. */
const actionRequiresAdminRotation = (state: TeamState, link: TeamLink) => {
  const { type, payload } = link.body
  switch (type) {
    case 'REMOVE_MEMBER': {
      return memberHasRole(state, payload.userId, ADMIN)
    }

    case 'REMOVE_MEMBER_ROLE': {
      return payload.roleName === ADMIN
    }

    case 'REMOVE_DEVICE': {
      return memberHasRole(state, identityRotationOwner(state, link), ADMIN)
    }

    case 'CHANGE_MEMBER_KEYS': {
      return memberHasRole(state, payload.keys.name, ADMIN)
    }

    case 'ROTATE_KEYS': {
      return memberHasRole(state, actingMemberId(state, link), ADMIN)
    }

    default: {
      return false
    }
  }
}

const memberHasRole = (state: TeamState, userId: string | undefined, roleName: string) =>
  userId !== undefined &&
  state.members.find(member => member.userId === userId)?.roles.includes(roleName) === true

const replacementRecipientForIdentityRotation = (
  previousState: TeamState,
  link: TeamLink,
  keys: Keyset,
  lockboxes: Lockbox[]
): RecipientManifest | undefined => {
  const owner = identityRotationOwner(previousState, link)
  if (owner === undefined || keys.type !== KeyType.USER || keys.name !== owner) return undefined

  const candidates = lockboxes.filter(
    ({ recipient }) =>
      recipient.type === keys.type &&
      recipient.name === keys.name &&
      recipient.generation === keys.generation + 1
  )
  const unique = uniqueRecipients(candidates.map(({ recipient }) => recipient))
  if (unique.length !== 1) return undefined

  const candidate = unique[0]
  const hasDelivery = lockboxes.some(
    ({ contents, recipient }) =>
      contents.type === KeyType.USER &&
      contents.name === owner &&
      contents.generation === candidate.generation &&
      contents.publicKey === candidate.publicKey &&
      recipient.type === KeyType.DEVICE
  )
  return hasDelivery ? candidate : undefined
}

const recipientIsExpectedForScope = (
  projectedState: TeamState,
  previousState: TeamState,
  link: TeamLink,
  contents: Lockbox['contents'],
  lockboxes: Lockbox[]
) => {
  const recipient = lockboxes[0]?.recipient
  if (recipient === undefined) return false
  const expected = expectedRecipientsForScope(
    projectedState,
    previousState,
    link,
    contents,
    lockboxes
  )
  return expected?.some(candidate => recipientId(candidate) === recipientId(recipient)) ?? false
}

const reachesExactly = (lockboxes: Lockbox[], expected: RecipientManifest[]) => {
  const reached = new Set(lockboxes.map(({ recipient }) => recipientId(recipient)))
  const expectedIds = new Set(expected.map(recipientId))
  return (
    reached.size === expectedIds.size && [...reached].every(recipient => expectedIds.has(recipient))
  )
}

const recipientList = (recipients: RecipientManifest[]) => recipients.map(recipientId).join(', ')

const uniqueRecipients = (recipients: RecipientManifest[]) => {
  const byId = new Map<string, RecipientManifest>()
  for (const recipient of recipients) byId.set(recipientId(recipient), recipient)
  return [...byId.values()]
}

const recipientForKeys = (keys: Keyset): RecipientManifest => ({
  type: keys.type,
  name: keys.name,
  generation: keys.generation,
  publicKey: keys.encryption,
})

const recipientForContents = (contents: Lockbox['contents']): RecipientManifest => ({
  type: contents.type,
  name: contents.name,
  generation: contents.generation,
  publicKey: contents.publicKey,
})

const recipientMatchesKeys = (recipient: RecipientManifest, keys: Keyset) =>
  recipientId(recipient) === recipientId(recipientForKeys(keys))

const recipientIsActiveDeviceOf = (
  state: TeamState,
  userId: string,
  recipient: RecipientManifest
) =>
  state.members
    .find(member => member.userId === userId)
    ?.devices?.some(device => recipientMatchesKeys(recipient, device.keys)) ?? false

const knownContents = (state: TeamState, contents: Lockbox['contents']) =>
  state.lockboxes.some(
    candidate =>
      isAuthorizationLockbox(candidate) &&
      candidate.contents.type === contents.type &&
      candidate.contents.name === contents.name &&
      candidate.contents.generation === contents.generation &&
      candidate.contents.publicKey === contents.publicKey &&
      candidate.contents.commitment === contents.commitment
  )

const currentSharedGeneration = (state: TeamState, scope: KeyScope): number | undefined => {
  const authorizationState = { ...state, lockboxes: state.lockboxes.filter(isAuthorizationLockbox) }
  return select.lockboxesInScope(authorizationState, scope)[0]?.contents.generation
}

const isTeamScope = (scope: KeyScope) => scope.type === KeyType.TEAM && scope.name === KeyType.TEAM

const isRoleScope = (scope: KeyScope, roleName: string) =>
  scope.type === KeyType.ROLE && scope.name === roleName

type KeyScope = { type: string; name: string }

type KeyIdentity = KeyScope & { generation: number }

/** TEAM and ROLE keys are shared by many holders; every other scope is one identity's own keys. */
const isSharedScope = (type: string) => type === KeyType.TEAM || type === KeyType.ROLE
const isIdentityScope = (type: string) => type === KeyType.USER || type === KeyType.SERVER

const scopeId = ({ type, name }: KeyScope) => `${type}:${name}`
const scopeKey = ({ type, name }: KeyScope) => JSON.stringify([type, name])
const keyIdentityId = ({ type, name, generation }: KeyIdentity) =>
  JSON.stringify([type, name, generation])
const recipientId = ({ type, name, generation, publicKey }: RecipientManifest) =>
  JSON.stringify([type, name, generation, publicKey])
const scopesMatch = (left: KeyScope, right: KeyScope) =>
  left.type === right.type && left.name === right.name
const scopeOf = ({ contents }: Lockbox): KeyScope => ({
  type: contents.type,
  name: contents.name,
})

const groupByKeyIdentity = (lockboxes: Lockbox[]): Map<string, Lockbox[]> => {
  const batches = new Map<string, Lockbox[]>()
  for (const lockbox of lockboxes) {
    const id = keyIdentityId(lockbox.contents)
    const batch = batches.get(id) ?? []
    batch.push(lockbox)
    batches.set(id, batch)
  }

  return batches
}

const establishedCommitments = (lockboxes: unknown): Map<string, string> => {
  const commitments = new Map<string, string>()
  if (!Array.isArray(lockboxes)) return commitments

  for (const candidate of lockboxes as unknown[]) {
    if (!isAuthorizationLockbox(candidate)) continue
    const { contents } = candidate
    const id = keyIdentityId(contents)
    if (!commitments.has(id)) commitments.set(id, contents.commitment)
  }

  return commitments
}

/** Extracts only the coordinates needed to associate a malformed manifest with its batch. */
const keyIdentity = (value: unknown): KeyIdentity | undefined => {
  if (!isRecord(value)) return undefined
  const candidate = value
  if (
    typeof candidate.type !== 'string' ||
    typeof candidate.name !== 'string' ||
    typeof candidate.generation !== 'number' ||
    !Number.isSafeInteger(candidate.generation) ||
    candidate.generation < 0
  ) {
    return undefined
  }

  return {
    type: candidate.type,
    name: candidate.name,
    generation: candidate.generation,
  }
}

/** Strict public structure check before attacker-controlled lockboxes reach any selector. */
const isAuthorizationLockbox = (value: unknown): value is Lockbox => {
  if (!isRecord(value) || !hasExactKeys(value, LOCKBOX_FIELDS)) return false
  if (!isRecord(value.encryptionKey) || !hasExactKeys(value.encryptionKey, ENCRYPTION_KEY_FIELDS)) {
    return false
  }

  return (
    value.encryptionKey.type === 'EPHEMERAL' &&
    value.encryptionKey.name === 'EPHEMERAL' &&
    isBase58KeyOfLength(value.encryptionKey.publicKey, 32) &&
    isRecipientManifest(value.recipient) &&
    isKeyManifest(value.contents) &&
    value.encryptedPayload instanceof Uint8Array
  )
}

const mayEstablishIdentityKeyset = (
  state: TeamState,
  link: TeamLink,
  manifest: Lockbox['contents']
): boolean => {
  const declaredByAction = identityKeysDeclaredByAction(link, manifest)
  if (declaredByAction !== undefined) return keysetMatchesManifest(declaredByAction, manifest)

  if (isAuthorizedIdentityRotation(state, link, manifest)) return true

  // A newly admitted member establishes the USER commitment when their already-registered device
  // posts PUBLISH_USER_KEYS_TO_DEVICE. The action-specific policy below also binds the delivery to
  // that exact device, so no other action can use this owner check as a distribution channel.
  if (manifest.type !== KeyType.USER || actingMemberId(state, link) !== manifest.name) return false
  const registered = state.members.find(member => member.userId === manifest.name)?.keys
  return registered !== undefined && keysetMatchesManifest(registered, manifest)
}

const identityKeysDeclaredByAction = (
  link: TeamLink,
  manifest: Lockbox['contents']
): Keyset | undefined => {
  const { type, payload } = link.body

  if (type === ROOT && manifest.type === KeyType.USER) return payload.rootMember.keys
  if (type === 'ADD_MEMBER' && manifest.type === KeyType.USER) return payload.member.keys
  if (type === 'CHANGE_MEMBER_KEYS' && manifest.type === KeyType.USER) return payload.keys
  if (type === 'ADD_SERVER' && manifest.type === KeyType.SERVER) return payload.server.keys
  if (type === 'CHANGE_SERVER_KEYS' && manifest.type === KeyType.SERVER) return payload.keys

  return undefined
}

const keysetMatchesManifest = (keys: Keyset, manifest: Lockbox['contents']) =>
  keys.type === manifest.type &&
  keys.name === manifest.name &&
  keys.generation === manifest.generation &&
  keys.encryption === manifest.publicKey

const isAuthorizedIdentityRotation = (
  state: TeamState,
  link: TeamLink,
  manifest: Lockbox['contents']
): boolean => {
  if (manifest.type !== KeyType.USER) return false
  const owner = identityRotationOwner(state, link)
  if (owner !== manifest.name) return false

  const latestGeneration = latestIdentityGeneration(state, manifest.type, manifest.name)
  return manifest.generation === latestGeneration + 1
}

const identityRotationOwner = (state: TeamState, link: TeamLink): string | undefined => {
  const { type, payload } = link.body
  if (type === 'REMOVE_MEMBER') return payload.userId
  if (type === 'REMOVE_DEVICE') {
    return state.members.find(member =>
      member.devices?.some(device => device.deviceId === payload.deviceId)
    )?.userId
  }

  return type === 'ROTATE_KEYS' ? actingMemberId(state, link) : undefined
}

const latestIdentityManifest = (
  state: TeamState,
  type: string,
  name: string
): Lockbox['contents'] | undefined => {
  let latest: Lockbox['contents'] | undefined
  for (const candidate of state.lockboxes as unknown[]) {
    if (
      !isAuthorizationLockbox(candidate) ||
      candidate.contents.type !== type ||
      candidate.contents.name !== name ||
      (latest !== undefined && candidate.contents.generation <= latest.generation)
    ) {
      continue
    }

    latest = candidate.contents
  }

  return latest
}

const latestIdentityGeneration = (state: TeamState, type: string, name: string): number => {
  const fromContents = latestIdentityManifest(state, type, name)?.generation ?? -1
  const fromRegistration =
    type === KeyType.USER
      ? state.members.find(member => member.userId === name)?.keys.generation
      : type === KeyType.SERVER
        ? state.servers.find(server => server.serverId === name)?.keys.generation
        : undefined
  return Math.max(fromContents, fromRegistration ?? -1)
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const actual = Object.keys(value)
  return actual.length === expected.length && expected.every(key => Object.hasOwn(value, key))
}

const LOCKBOX_FIELDS = ['encryptionKey', 'recipient', 'contents', 'encryptedPayload'] as const
const ENCRYPTION_KEY_FIELDS = ['type', 'name', 'publicKey'] as const

/**
 * The member a link acts as: the owner of the signing device, or the server itself.
 *
 * This re-resolves the signer rather than taking the author `validate` already derived, but it does
 * no crypto — by the time transforms run, `validate` has verified the link's signature against this
 * same record.
 */
const actingMemberId = (state: TeamState, link: TeamLink): string | undefined => {
  const record = select.signerRecord(state, link.body.signer, { includeRemoved: true })
  if (record === undefined) return undefined
  return record.kind === SignerKind.DEVICE ? record.device.userId : record.server.serverId
}
