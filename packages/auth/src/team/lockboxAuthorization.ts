import { type Logger } from '@localfirst/shared'
import { type Lockbox } from 'lockbox/index.js'
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
  lockboxes: Lockbox[],
  logger: Logger
): Lockbox[] => {
  // The shared scopes this link's lockboxes distribute keys for.
  const scopes = new Map<string, KeyScope>()
  for (const { contents } of lockboxes) {
    if (!isSharedScope(contents.type)) continue
    scopes.set(scopeId(contents), { type: contents.type, name: contents.name })
  }

  if (scopes.size === 0) return lockboxes

  const dropped = new Set<Lockbox>()
  const drop = (rejects: Lockbox[], scope: KeyScope, reason: string) => {
    if (rejects.length === 0) return
    for (const lockbox of rejects) dropped.add(lockbox)
    logger.warn(
      `Dropping ${rejects.length} lockbox(es) for ${scopeId(scope)} from link ${link.hash}: ${reason}`
    )
  }

  for (const scope of scopes.values()) {
    const prior = select.lockboxesInScope(state, scope)

    // No prior lockboxes means this scope is being *created*, not re-keyed. Creating one is
    // authorized by the action (ADD_ROLE is admin-only; ROOT establishes the team's own keys), and
    // there is no holder set to preserve yet.
    if (prior.length === 0) continue

    const currentGeneration = prior[0].contents.generation
    const inScope = lockboxes.filter(({ contents }) => scopeId(contents) === scopeId(scope))

    // A generation identifies one keyset, not merely a position in the key history. Distributing
    // the established generation to a new recipient is legitimate, but introducing a different key
    // at that generation would let the later lockbox replace the established key in `keyMap`.
    const currentPublicKeys = new Set(prior.map(({ contents }) => contents.publicKey))
    drop(
      inScope.filter(
        ({ contents }) =>
          contents.generation === currentGeneration && !currentPublicKeys.has(contents.publicKey)
      ),
      scope,
      `generation ${currentGeneration} is already bound to another key`
    )

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
        prior.some(
          ({ recipient }) =>
            (recipient.type === KeyType.USER || recipient.type === KeyType.SERVER) &&
            recipient.name === author
        ))
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

    // No divergent keys — an authorized insider must not be able to partition the scope by handing
    // its holders different keysets under one generation number.
    if (new Set(next.map(({ contents }) => contents.publicKey)).size > 1) {
      drop(next, scope, 'distributes divergent keys to its holders')
      continue
    }

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
    const reached = new Set(next.map(recipientId))
    const missed = [...new Set(prior.map(recipientId))].filter(holder => !reached.has(holder))
    if (missed.length > 0) {
      drop(next, scope, `does not reach current holders [${missed.join(', ')}]`)
    }
  }

  return dropped.size === 0 ? lockboxes : lockboxes.filter(lockbox => !dropped.has(lockbox))
}

type KeyScope = { type: string; name: string }

/** TEAM and ROLE keys are shared by many holders; every other scope is one identity's own keys. */
const isSharedScope = (type: string) => type === KeyType.TEAM || type === KeyType.ROLE

const scopeId = ({ type, name }: KeyScope) => `${type}:${name}`
const recipientId = ({ recipient }: Lockbox) => scopeId(recipient)

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
