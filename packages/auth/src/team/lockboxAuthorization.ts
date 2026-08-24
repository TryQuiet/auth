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
import { SignerKind, type TeamLink, type TeamState } from './types.js'

/**
 * Decides which of a link's lockboxes may be applied to the team's state.
 *
 * Lockboxes distribute keys, and they ride on *any* link's payload: the reducer sweeps them in
 * regardless of what action the link is taking. For a member's own (USER / DEVICE / SERVER) keys
 * that's fine — those are governed by `canOnlyChangeYourOwnKeys`. But TEAM and ROLE keys are
 * *shared*, honest clients adopt the highest generation they can see for a scope, and a keyset is
 * just a random keypair anyone can mint. So without this, introducing a new generation of a shared
 * key was an unauthorized primitive: a non-admin who is not even in a role (a Quiet "private
 * channel") could mint a next-generation role keyset, hand it to a subset that leaves out the real
 * members, and have honest clients silently encrypt future channel traffic under a key she holds —
 * effective removal of the excluded members plus takeover of the channel (#61).
 *
 * A link that introduces a *higher* generation than the team has for a TEAM or ROLE scope is a
 * re-key, and must satisfy all of:
 *
 *   (a) the author holds that scope's key — an admin, or a member/server the current generation is
 *       already boxed to. Whoever mints a keyset knows it, so an outsider must not get to introduce
 *       one.
 *   (b) it increments the current generation by exactly one — no gaps, no leapfrogging to a number
 *       that would outrank every honest rotation forever.
 *   (c) it reaches every one of the scope's current holders, all under one key: no silent
 *       exclusions, no handing different holders divergent keysets. The holder set is read from the
 *       recipients of the scope's current-generation lockboxes, which is precisely what the honest
 *       rotation path (`Team.rotateKeys` -> `lockboxesInScope`) re-boxes to.
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
  state: TeamState,
  link: TeamLink,
  lockboxes: unknown,
  logger: Logger
): Lockbox[] => {
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
  const established = establishedCommitments(state.lockboxes)
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
      !mayEstablishIdentityKeyset(state, link, batch[0].contents)
    ) {
      drop(
        batch,
        scope,
        `generation ${batch[0].contents.generation} is not established by its identity owner`
      )
    }
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
    ...state,
    lockboxes: state.lockboxes.filter(isAuthorizationLockbox),
  }
  for (const scope of scopes.values()) {
    const prior = select.lockboxesInScope(authorizationState, scope)
    const inScope = validLockboxes.filter(
      lockbox =>
        !dropped.has(lockbox) &&
        isKeyManifest(lockbox.contents) &&
        scopesMatch(lockbox.contents, scope)
    )

    // No prior lockboxes can mean the scope is being created, but a ROLE scope only exists once its
    // ADD_ROLE action creates it. Otherwise anyone could pre-seed a future role with a high
    // generation and have that key outrank the legitimate generation-zero key when the role is
    // eventually added.
    if (prior.length === 0) {
      const roleAlreadyExists =
        scope.type === KeyType.ROLE && state.roles.some(role => role.roleName === scope.name)
      const createsThisRole =
        (link.body.type === 'ADD_ROLE' && link.body.payload.roleName === scope.name) ||
        (link.body.type === ROOT && scope.name === ADMIN)
      if (scope.type === KeyType.ROLE && !roleAlreadyExists && !createsThisRole) {
        drop(inScope, scope, 'role does not exist yet')
      }

      continue
    }

    const currentGeneration = prior[0].contents.generation
    const rekey = inScope.filter(({ contents }) => contents.generation > currentGeneration)

    // Not a re-key. Handing out a generation the team already has — a role key to a new role member,
    // or (since a member admitted after a rotation needs the older generations to read history) every
    // team-key generation to a joiner — is governed by the membership validators, not here.
    if (rekey.length === 0) continue

    // (a) Only a current holder of the scope may introduce a new generation of it. `author` is the
    // signer resolved from the link's signature, not anything the body claims about itself.
    const author = actingMemberId(state, link)
    const authorHoldsScope =
      author !== undefined &&
      (select.memberIsAdmin(state, author) ||
        prior.some(({ recipient }) => recipientIsCurrentIdentity(state, author, recipient)))
    if (!authorHoldsScope) {
      drop(rekey, scope, `'${author ?? 'unknown signer'}' does not hold this key`)
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

    // (c) The new generation goes to the scope's current holders, all under one key.

    // Divergent commitments were rejected as one batch above, before any new generation could be
    // established. Every surviving recipient therefore gets the exact same complete keyset.

    // No silent exclusions. Every current holder has to be re-boxed; leaving one out is how a
    // re-key becomes an eviction that no REMOVE_MEMBER / REMOVE_MEMBER_ROLE link ever recorded.
    // This is what stops the attack on the *team* key, which (a) can't: every member holds that
    // one, so scope authority alone lets any of them rotate it. (Honest removals pass: they re-box
    // to the removed member too, and the removal's own reducer is what takes their access away.)
    //
    // Only exclusions are checked, not set equality. An *extra* recipient is not a boundary anyone
    // is defending: any holder can hand the current generation to an arbitrary keyset with
    // `ADD_LOCKBOXES` (`Team.createLockbox`), no rotation needed — that's the separate
    // recipient-authorization gap (#18 / #25). Meanwhile a set-equality check reads `prior` as if it
    // were complete, which it isn't during `decryptTeamGraph`'s per-path walk, where state carries
    // only one lineage. Checking exclusions is safe there: a partial `prior` can only shrink the
    // holder set, so the check gets more lenient, never more strict.
    const reached = new Set(next.map(({ recipient }) => recipientId(recipient)))
    const expectedHolders = prior.map(({ recipient }) =>
      recipientId(expectedRecipientForLink(state, recipient, link, next))
    )
    const missed = [...new Set(expectedHolders)].filter(holder => !reached.has(holder))
    if (missed.length > 0) {
      drop(next, scope, `does not reach current holders [${missed.join(', ')}]`)
    }
  }

  return validLockboxes.filter(lockbox => !dropped.has(lockbox))
}

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
  // posts `Team.join`. Requiring the resolved signer to own that USER scope prevents every other
  // member from pre-seeding it while retaining the invitation flow.
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

/** A claimed holder must use the latest authorized recipient generation/key for that identity. */
const recipientIsCurrentIdentity = (
  state: TeamState,
  identityId: string,
  recipient: RecipientManifest
): boolean => {
  if (recipient.name !== identityId) return false
  const registered =
    recipient.type === KeyType.USER
      ? state.members.find(member => member.userId === identityId)?.keys
      : recipient.type === KeyType.SERVER
        ? state.servers.find(server => server.serverId === identityId)?.keys
        : undefined

  const latestContents = latestIdentityManifest(state, recipient.type, identityId)
  if (latestContents !== undefined && latestContents.generation >= (registered?.generation ?? -1)) {
    return (
      recipient.generation === latestContents.generation &&
      recipient.publicKey === latestContents.publicKey
    )
  }

  return registered !== undefined && keysetMatchesRecipient(registered, recipient)
}

/** Honest key changes re-address every affected lockbox to the newly declared recipient keys. */
const expectedRecipientForLink = (
  state: TeamState,
  recipient: RecipientManifest,
  link: TeamLink,
  next: Lockbox[]
): RecipientManifest => {
  const { type, payload } = link.body
  const updatedKeys =
    type === 'CHANGE_MEMBER_KEYS' && recipient.type === KeyType.USER
      ? payload.keys
      : type === 'CHANGE_SERVER_KEYS' && recipient.type === KeyType.SERVER
        ? payload.keys
        : undefined

  if (
    updatedKeys !== undefined &&
    updatedKeys.type === recipient.type &&
    updatedKeys.name === recipient.name
  ) {
    return {
      type: updatedKeys.type,
      name: updatedKeys.name,
      generation: updatedKeys.generation,
      publicKey: updatedKeys.encryption,
    }
  }

  // Removal-driven rotations deliberately mint replacement recipient keys that are not installed
  // in the public identity record: their purpose is to cut the compromised member/device off. The
  // link therefore has no separate public key declaration to compare against. Accept exactly one
  // canonical next recipient manifest for the affected identity; an unrelated action gets no such
  // transition and must reproduce the old manifest exactly.
  if (!linkMayRotateRecipientWithoutDeclaration(state, link, recipient)) return recipient
  const candidates = new Map<string, RecipientManifest>()
  for (const { recipient: candidate } of next) {
    if (
      candidate.type === recipient.type &&
      candidate.name === recipient.name &&
      candidate.generation === recipient.generation + 1
    ) {
      candidates.set(recipientId(candidate), candidate)
    }
  }

  return candidates.size === 1 ? [...candidates.values()][0] : recipient
}

const keysetMatchesRecipient = (keys: Keyset, recipient: RecipientManifest) =>
  keys.type === recipient.type &&
  keys.name === recipient.name &&
  keys.generation === recipient.generation &&
  keys.encryption === recipient.publicKey

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

const linkMayRotateRecipientWithoutDeclaration = (
  state: TeamState,
  link: TeamLink,
  recipient: RecipientManifest
): boolean => {
  const { type, payload } = link.body
  if (type === 'REMOVE_MEMBER') {
    return recipient.type === KeyType.USER && recipient.name === payload.userId
  }

  if (type === 'REMOVE_DEVICE') {
    const owner = identityRotationOwner(state, link)
    return (
      (recipient.type === KeyType.DEVICE && recipient.name === payload.deviceId) ||
      (recipient.type === KeyType.USER && recipient.name === owner)
    )
  }

  if (type === 'ROTATE_KEYS') {
    return recipient.type === KeyType.USER && recipient.name === actingMemberId(state, link)
  }

  return false
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
