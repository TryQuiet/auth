import { getSequence } from '@localfirst/crdx'
import { randomKey, type Base58 } from '@localfirst/crypto'
import { pause } from '@localfirst/shared'
import {
  ADMISSION_NOT_PERSISTED,
  ADMIT_MEMBER_LINK_MISSING,
  IDENTITY_ALREADY_CLAIMED,
} from 'connection/errors.js'
import { findExistingAdmission } from 'connection/existingAdmission.js'
import { CONNECTION_PROTOCOL_VERSION, type ConnectionMessage } from 'connection/message.js'
import type {
  ConnectionParams,
  InviteeMemberContext,
  PriorInvitationProof,
  ServerContext,
} from 'connection/types.js'
import { deriveId, generateProof, type MemberInvitationClaim } from 'invitation/index.js'
import { pack, unpack } from 'msgpackr'
import { createServer, redactServer, type Server, type ServerWithSecrets } from 'server/index.js'
import { load as loadTeam, type Team } from 'team/index.js'
import { membershipResolver } from 'team/membershipResolver.js'
import {
  invitationNonces,
  joinTestChannel,
  memberClaim,
  memberPossessionProof,
  setup,
  TestChannel,
  type UserStuff,
} from 'util/testing/index.js'
import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * The durable-admission gate: private#203, audit finding QSS-006 ("Admission Acceptance Can
 * Precede the Admitting Peer's Durable Sigchain Write"), threat-model invariant C3 "Option A".
 *
 * Before this fix, `acceptInvitation` admitted the invitee into the in-memory team and queued
 * ACCEPT_INVITATION — the team graph and the team keyring — in the same synchronous action.
 * `Team.dispatch` emits `updated` synchronously but every consumer of that event (the Quiet client
 * writing LevelDB, QSS writing PostgreSQL) persists asynchronously and nothing awaited them. An
 * admitter that crashed in that window restarted with no ADMIT link while the invitee already held
 * the team keys, and would then reject that invitee with DEVICE_UNKNOWN forever.
 *
 * Option A: validate, sign, append AND durably persist the admission before releasing the graph or
 * the keys. If the durable write can't be confirmed, the invitee gets nothing at all — it still
 * holds only its invitation, which it can present again.
 *
 * These tests drive two real `Connection`s over a `TestChannel` and watch the admitter's outgoing
 * wire, because "no acceptance was sent" is a claim about bytes, not about internal state.
 */
describe('connection', () => {
  describe('durable admission gate (persistAdmission)', () => {
    beforeEach(() => {
      vi.useRealTimers()
    })

    describe('a member admitter', () => {
      it('sends no acceptance while the durable write is still in flight', async () => {
        const { alice, charlie, inviteeContext } = invite()
        const gate = deferred()

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            return gate.promise
          },
        })
        const { wire, admitter, invitee } = pair

        // The admission is on the admitter's in-memory graph...
        await waitUntil(() => gate.calls === 1)
        expect(alice.team.has(charlie.userId)).toBe(true)

        // ...but nothing has gone out. Give the machine and the message queue room to misbehave.
        await pause(50)
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()

        // Once the application confirms the write, the acceptance goes out through the normal
        // queue and the handshake completes as it always did.
        gate.resolve()
        await pair.bothConnected()
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(1)
        expect(invitee.team!.has(charlie.userId)).toBe(true)
        expect(invitee._sessionKey).toEqual(admitter._sessionKey)
      })

      it('sends no acceptance at all when the durable write fails', async () => {
        const { alice, inviteeContext } = invite()

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('disk on fire')
          },
        })
        const { wire, admitter, invitee } = pair

        expect(await pair.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)

        // Nothing was released: no acceptance on the wire, no team, no keys, no `joined`.
        await pause(50)
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()
        expect(invitee._sessionKey).toBeUndefined()
        expect(pair.log.joined).toBe(0)
        expect(admitter.state).toBe('disconnected')
      })

      it('releases nothing if the connection is torn down mid-write', async () => {
        // A crash is the scenario QSS-006 is about, and the closest a test can get to one is a
        // teardown while the durable write is still outstanding. Whatever the write goes on to do,
        // no graph and no keyring may leave a connection that is no longer running — and a
        // stopped connection cannot be revived to flush one later (private#203 audit L-3).
        const { alice, inviteeContext } = invite()
        const gate = deferred()
        let signal: AbortSignal | undefined

        const { wire, admitter, invitee } = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission(_team, options) {
            signal = options?.signal
            return gate.promise
          },
        })

        await waitUntil(() => gate.calls === 1)
        expect(signal?.aborted).toBe(false)

        admitter.stop()
        invitee.stop()

        // Stopping stops the machine's actor, so the hook is told nobody is waiting any more.
        expect(signal?.aborted).toBe(true)

        gate.resolve()
        await pause(50)
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()

        // And the acceptance cannot be flushed by restarting the same object.
        expect(() => admitter.start()).toThrow()
        await pause(50)
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
      })

      it('releases nothing if the peer disconnects mid-write', async () => {
        // DISCONNECT used to be handled only in `connected`, so a peer hanging up during the
        // durable write was ignored and the invoked actor outlived the session.
        const { alice, inviteeContext } = invite()
        const gate = deferred()
        let signal: AbortSignal | undefined

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission(_team, options) {
            signal = options?.signal
            return gate.promise
          },
        })

        await waitUntil(() => gate.calls === 1)
        pair.injectFromInvitee({ type: 'DISCONNECT' })
        await waitUntil(() => pair.admitter.state === 'disconnected')
        expect(signal?.aborted).toBe(true)

        gate.resolve()
        await pause(50)
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(pair.invitee.team).toBeUndefined()
      })

      /**
       * What the gate does NOT cover (private#203 audit L-1). `team.admitMember` emits `updated`
       * synchronously, and every connection already listening to that same `Team` sends a SYNC
       * straight away — before, and independently of, the admitting peer's durable write. So the
       * gate withholds the acceptance from the invitee, not the new head from established peers.
       *
       * This is current, deliberate behaviour, not a team-wide durable-head barrier. It is pinned
       * here so the claim in the docstrings stays honest: those peers receive the head early and
       * persist it through their own gates. Nothing an unadmitted invitee can read is released.
       */
      it('still syncs the new head to peers that are already connected', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const inviteeContext: InviteeMemberContext = {
          user: charlie.user,
          device: charlie.device,
          invitationSeed: seed,
          expectedTeamId: alice.team.id,
        }

        // An ordinary established connection between two members, sharing Alice's Team object.
        const peerChannel = new TestChannel()
        const peerMessages: Array<{ senderId: string; message: ConnectionMessage }> = []
        peerChannel.addListener('data', (senderId, message) => {
          peerMessages.push({ senderId, message: unpack(message) as ConnectionMessage })
        })
        const peerJoin = joinTestChannel(peerChannel)
        const aliceToBob = peerJoin(alice.connectionContext)
        const bobToAlice = peerJoin(bob.connectionContext)
        aliceToBob.start()
        bobToAlice.start()
        await waitUntil(() => aliceToBob.state === 'connected' && bobToAlice.state === 'connected')
        await pause(50)

        const alicesSyncs = () =>
          peerMessages.filter(m => m.senderId === alice.deviceId && m.message.type === 'SYNC')
        const before = alicesSyncs().length

        const gate = deferred()
        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            return gate.promise
          },
        })

        await waitUntil(() => gate.calls === 1)
        await pause(50)

        // The invitee is told nothing while the write is outstanding...
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        // ...but Bob already has the admission.
        expect(alicesSyncs().length).toBeGreaterThan(before)
        expect(bobToAlice.team!.has(charlie.userId)).toBe(true)

        gate.resolve()
        await pair.bothConnected()
        aliceToBob.stop()
        bobToAlice.stop()
      })

      it('behaves exactly as before when no hook is supplied', async () => {
        const { alice, charlie, inviteeContext } = invite()

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
        })

        await pair.bothConnected()
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(1)
        expect(pair.invitee.team!.has(charlie.userId)).toBe(true)
      })
    })

    describe('a server admitter', () => {
      it('sends no acceptance while the durable write is still in flight', async () => {
        const { alice, charlie, inviteeContext } = invite()
        const server = addServerTo(alice)
        const gate = deferred()

        const pair = connectInvitee({
          admitterContext: server.connectionContext,
          inviteeContext,
          async persistAdmission() {
            return gate.promise
          },
        })
        const { wire, invitee } = pair

        await waitUntil(() => gate.calls === 1)
        expect(server.team.has(charlie.userId)).toBe(true)
        await pause(50)
        expect(wire.from(server.host, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()

        gate.resolve()
        await pair.bothConnected()
        expect(wire.from(server.host, 'ACCEPT_INVITATION')).toHaveLength(1)
        expect(invitee.team!.has(charlie.userId)).toBe(true)
      })

      it('sends no acceptance at all when the durable write fails', async () => {
        const { alice, inviteeContext } = invite()
        const server = addServerTo(alice)

        const pair = connectInvitee({
          admitterContext: server.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('postgres is down')
          },
        })
        const { wire, invitee } = pair

        expect(await pair.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)

        await pause(50)
        expect(wire.from(server.host, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()
        expect(invitee._sessionKey).toBeUndefined()
      })
    })

    /**
     * Invariant D5: a failed attempt must leave the invitee able to reach the next complete valid
     * state by retrying. The two ways a durable write can fail leave the admitter in different
     * places, so they're tested separately.
     */
    describe('retrying after a failed durable write', () => {
      it('admits the invitee when the admitter restarts from its last durable graph', async () => {
        const { alice, charlie, inviteeContext } = invite()

        // Whatever the admitter last got onto disk. The admission below never joins it — that is
        // precisely what "the durable write failed" means.
        const durableGraph = alice.team.save()
        const teamKeyring = alice.team.teamKeyring()

        const first = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('disk on fire')
          },
        })
        expect(await first.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)
        expect(first.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        first.stop()

        // The admitter restarts and rebuilds its team from durable storage, which never saw the
        // admission. The invitee still holds nothing but its invitation, so it just reconnects.
        const restarted = loadTeam(durableGraph, alice.localContext, teamKeyring)
        expect(restarted.has(charlie.userId)).toBe(false)

        const second = connectInvitee({
          admitterContext: { user: alice.user, device: alice.device, team: restarted },
          inviteeContext: retryContext(inviteeContext),
          async persistAdmission() {},
        })

        await second.bothConnected()
        expect(second.invitee.team!.has(charlie.userId)).toBe(true)
        expect(effectiveAdmissions(restarted, charlie.userId)).toHaveLength(1)
      })

      /**
       * The other failure mode: the durable write failed but the process survived, so the ADMIT
       * link is still on the admitter's in-memory graph.
       *
       * The retry recognizes that earlier admission of this exact claim and appends nothing — a
       * re-dispatch would throw `The id '…' is already in use`, and since ids are unique this
       * admitter could then never admit this invitee again. It runs the durable write instead,
       * which is the step that failed, and sends the acceptance.
       *
       * The invitee only accepts that acceptance because it was told to expect the older proof.
       * Rule 6 of `validateInvitationAcceptance` requires this handshake's proof, which is what
       * stops an acceptor wrapping a stale graph in a fresh envelope; the application carries
       * `Connection.invitationAttempt` across from the failed attempt to widen it by that one
       * link, scoped to the peer it was presented to.
       */
      it('completes the admission when the write is retried against the same in-memory team', async () => {
        const { alice, charlie, inviteeContext } = invite()
        const persisted: Team[] = []

        const first = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('disk on fire')
          },
        })
        expect(await first.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)

        // What the application remembers about the attempt that failed.
        const attempt = first.invitee.invitationAttempt
        expect(attempt).toBeDefined()
        expect(attempt!.presentedTo).toBe(alice.deviceId)
        first.stop()

        expect(alice.team.has(charlie.userId)).toBe(true)

        const second = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext: retryContext(inviteeContext, attempt!),
          async persistAdmission(team: Team) {
            persisted.push(team)
          },
        })

        // The durable write is retried, and this time the acceptance goes out...
        await second.bothConnected()
        expect(second.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(1)
        expect(persisted).toHaveLength(1)
        expect(persisted[0].has(charlie.userId)).toBe(true)

        // ...the invitee joins...
        expect(second.log.joined).toBe(1)
        expect(second.invitee.team!.has(charlie.userId)).toBe(true)
        expect(second.log.localErrors.invitee).toEqual([])

        // ...and nothing new was appended: the identity is registered exactly once.
        expect(effectiveAdmissions(alice.team, charlie.userId)).toHaveLength(1)
      })

      // Without the remembered proof the same retry fails closed rather than silently accepting a
      // graph whose admission belongs to another handshake. This is the property audit finding M-1
      // is about, checked from the side that has to live with it.
      it('refuses the same retry when the application remembered nothing', async () => {
        const { alice, charlie, inviteeContext } = invite()

        const first = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('disk on fire')
          },
        })
        expect(await first.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)
        first.stop()

        const second = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext: retryContext(inviteeContext),
          async persistAdmission() {},
        })

        expect(await second.firstLocalError('invitee')).toBe(ADMIT_MEMBER_LINK_MISSING)
        expect(second.invitee.team).toBeUndefined()
        expect(effectiveAdmissions(alice.team, charlie.userId)).toHaveLength(1)
      })

      // The memory is scoped to the peer the proof was presented to, so it cannot be handed to
      // anyone else — that scoping is what keeps it from reopening the rollback M-1 describes.
      it('refuses a remembered proof presented to a different peer', async () => {
        const { alice, charlie, inviteeContext } = invite()

        const first = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            throw new Error('disk on fire')
          },
        })
        expect(await first.firstLocalError('admitter')).toBe(ADMISSION_NOT_PERSISTED)
        const attempt = first.invitee.invitationAttempt!
        first.stop()

        const second = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext: retryContext(inviteeContext, {
            ...attempt,
            presentedTo: charlie.deviceId,
          }),
          async persistAdmission() {},
        })

        expect(await second.firstLocalError('invitee')).toBe(ADMIT_MEMBER_LINK_MISSING)
        expect(second.invitee.team).toBeUndefined()
      })
    })

    /**
     * `REQUEST_IDENTITY` used to be a root-level transition back into `awaitingIdentityClaim`, so
     * a peer could restart identity negotiation from any state — including one that had already
     * admitted it. The audit's probe turned that into a second durable write and a second
     * ACCEPT_INVITATION carrying the team graph and keyring, which an invitation holder could
     * repeat at will (private#203 audit M-4).
     */
    describe('repeated identity requests', () => {
      it('does not restart the durable write while one is in flight', async () => {
        const { alice, inviteeContext } = invite()
        const gate = deferred()

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            return gate.promise
          },
        })

        await waitUntil(() => gate.calls === 1)
        for (let attempt = 0; attempt < 3; attempt++) pair.injectFromInvitee(requestIdentity())

        expect(await pair.firstLocalError('admitter')).toBe(IDENTITY_ALREADY_CLAIMED)

        // Leaving the state stops the invoked actor, so the held promise settling later changes
        // nothing: one hook call, no acceptance.
        gate.resolve()
        await pause(50)
        expect(gate.calls).toBe(1)
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(pair.admitter.state).toBe('disconnected')
      })

      it('does not re-admit or re-send the acceptance after admission completed', async () => {
        const { alice, charlie, inviteeContext } = invite()
        let calls = 0

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            calls += 1
          },
        })

        await pair.bothConnected()
        await pause(50)
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(1)

        for (let attempt = 0; attempt < 3; attempt++) pair.injectFromInvitee(requestIdentity())

        expect(await pair.firstLocalError('admitter')).toBe(IDENTITY_ALREADY_CLAIMED)
        await pause(50)
        expect(calls).toBe(1)
        expect(pair.wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(1)
        expect(pair.admitter.state).toBe('disconnected')
        expect(effectiveAdmissions(alice.team, charlie.userId)).toHaveLength(1)
      })

      it('still answers the opening identity request', async () => {
        // The negotiation itself is unchanged: the first request is what makes us send our claim.
        const { alice, charlie, inviteeContext } = invite()

        const pair = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {},
        })

        await pair.bothConnected()
        expect(pair.wire.from(alice.deviceId, 'CLAIM_IDENTITY')).toHaveLength(1)
        expect(pair.invitee.team!.has(charlie.userId)).toBe(true)
      })
    })

    /**
     * Unit-level checks on the predicate that makes the retry above idempotent. "Already admitted"
     * has to mean *this* identity by *this* invitation and nothing looser, because the consequence
     * of a match is handing over the team keyring without writing anything new.
     */
    describe('findExistingAdmission', () => {
      it('recognizes an admission of this exact claim by this invitation', () => {
        const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const { proof, claim, possessionProof } = admission(seed, charlie)

        expect(
          findExistingAdmission({ team: alice.team, invitationId: proof.id, claim })
        ).toBeUndefined()

        alice.team.admitMember(proof, claim, possessionProof)

        expect(
          findExistingAdmission({ team: alice.team, invitationId: proof.id, claim })
        ).toBeDefined()
      })

      it('ignores an admission whose proof came from another handshake', () => {
        // The claim is what names the identity and it is signed by the invitee's own device key.
        // The proof is per-handshake, so a retry necessarily presents a different one; matching on
        // the proof would make the predicate useless for its only purpose.
        const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const first = admission(seed, charlie)
        alice.team.admitMember(first.proof, first.claim, first.possessionProof)

        const retry = admission(seed, charlie)
        expect(retry.proof).not.toEqual(first.proof)
        expect(
          findExistingAdmission({
            team: alice.team,
            invitationId: retry.proof.id,
            claim: retry.claim,
          })
        ).toBeDefined()
      })

      it('refuses a claim whose keys differ from the registered identity', () => {
        const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const { proof, claim, possessionProof } = admission(seed, charlie)
        alice.team.admitMember(proof, claim, possessionProof)

        const rekeyed = {
          ...claim,
          memberKeys: { ...claim.memberKeys, encryption: 'not the registered key' },
        } as MemberInvitationClaim
        expect(
          findExistingAdmission({ team: alice.team, invitationId: proof.id, claim: rekeyed })
        ).toBeUndefined()

        const otherDevice = {
          ...claim,
          device: { ...claim.device, deviceId: 'some other device' },
        } as MemberInvitationClaim
        expect(
          findExistingAdmission({ team: alice.team, invitationId: proof.id, claim: otherDevice })
        ).toBeUndefined()
      })

      it('refuses a claim admitted by some other invitation', () => {
        const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const { proof, claim, possessionProof } = admission(seed, charlie)
        alice.team.admitMember(proof, claim, possessionProof)

        const other = alice.team.inviteMember()
        expect(
          findExistingAdmission({ team: alice.team, invitationId: other.id, claim })
        ).toBeUndefined()
      })

      it('refuses a claim whose identity has been removed', () => {
        const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
        const { seed } = alice.team.inviteMember()
        const { proof, claim, possessionProof } = admission(seed, charlie)
        alice.team.admitMember(proof, claim, possessionProof)
        alice.team.remove(charlie.userId)

        expect(
          findExistingAdmission({ team: alice.team, invitationId: proof.id, claim })
        ).toBeUndefined()
      })
    })
  })
})

/** Everything an invitee hands over to be admitted as a new member, for one fresh handshake. */
const admission = (seed: string, invitee: UserStuff) => {
  const claim = memberClaim(invitee.user, invitee.device)
  return {
    proof: generateProof({ seed, claim, ...invitationNonces() }),
    claim,
    possessionProof: memberPossessionProof(deriveId(seed), invitee.user, invitee.device),
  }
}

// HELPERS

/** A well-formed opening identity request, valid at any point in the protocol. */
const requestIdentity = (): ConnectionMessage => ({
  type: 'REQUEST_IDENTITY',
  payload: {
    protocolVersion: CONNECTION_PROTOCOL_VERSION,
    identityNonce: randomKey() as Base58,
  },
})

/** Alice invites Charlie; returns the invitee context his connection will present. */
const invite = () => {
  const { alice, charlie } = setup('alice', { user: 'charlie', member: false })
  const { seed } = alice.team.inviteMember()
  const inviteeContext: InviteeMemberContext = {
    user: charlie.user,
    device: charlie.device,
    invitationSeed: seed,
    expectedTeamId: alice.team.id,
  }
  return { alice, charlie, inviteeContext }
}

/**
 * The same invitee reconnecting: same seed, same user, same device — so the same claim, signed
 * again. Only the handshake nonces differ, and those are chosen inside the connection.
 *
 * `priorInvitationProofs` is what an application carries across from a failed attempt, exactly as
 * the Quiet adapters do: read `Connection.invitationAttempt`, keep it for the retry, drop it once
 * a join succeeds.
 */
const retryContext = (
  context: InviteeMemberContext,
  ...priorInvitationProofs: PriorInvitationProof[]
): InviteeMemberContext => ({
  ...context,
  ...(priorInvitationProofs.length > 0 && { priorInvitationProofs }),
})

type ServerStuff = {
  host: string
  server: Server
  serverWithSecrets: ServerWithSecrets
  team: Team
  connectionContext: ServerContext
}

/** Adds a QSS-style relay server to Alice's team and gives it its own copy of the graph. */
const addServerTo = (alice: UserStuff): ServerStuff => {
  const host = 'example.com'
  const serverWithSecrets = createServer({ host, seed: host })
  const server = redactServer(serverWithSecrets)
  alice.team.addServer(server)
  const team = loadTeam(alice.team.save(), { server: serverWithSecrets }, alice.team.teamKeyring())
  return {
    host,
    server,
    serverWithSecrets,
    team,
    connectionContext: { server: serverWithSecrets, team },
  }
}

/**
 * Wires an admitter and an invitee together over a test channel, recording every message each side
 * actually puts on the wire.
 */
const connectInvitee = ({
  admitterContext,
  inviteeContext,
  persistAdmission,
}: {
  admitterContext: Parameters<ReturnType<typeof joinTestChannel>>[0]
  inviteeContext: InviteeMemberContext
  persistAdmission?: ConnectionParams['persistAdmission']
}) => {
  const channel = new TestChannel()
  const messages: Array<{ senderId: string; message: ConnectionMessage }> = []
  channel.addListener('data', (senderId, message) => {
    messages.push({ senderId, message: unpack(message) as ConnectionMessage })
  })

  const join = joinTestChannel(channel)
  const admitter = join(admitterContext, { persistAdmission })
  const invitee = join(inviteeContext)

  const wire = {
    from: (senderId: string, type: ConnectionMessage['type']) =>
      messages.filter(m => m.senderId === senderId && m.message.type === type),
  }

  const inviteeId = inviteeContext.device.deviceId

  /**
   * Puts a message on the wire as if the invitee had sent it, numbered so the admitter's message
   * queue delivers it immediately rather than holding it for a gap.
   */
  const injectFromInvitee = (message: ConnectionMessage) => {
    const indexes = messages
      .filter(m => m.senderId === inviteeId)
      .map(m => (m.message as unknown as { index: number }).index)
    const index = Math.max(-1, ...indexes) + 1
    const packed = pack({ ...message, index })
    channel.write(inviteeId, Uint8Array.from(packed))
  }

  // Subscribed before either side starts, so a test never has to attach a listener to an event
  // that may already have fired. Everything below is asserted against this log.
  const log = {
    localErrors: { admitter: [] as string[], invitee: [] as string[] },
    connected: { admitter: false, invitee: false },
    joined: 0,
  }
  admitter.on('localError', error => log.localErrors.admitter.push(error.type))
  invitee.on('localError', error => log.localErrors.invitee.push(error.type))
  admitter.on('connected', () => {
    log.connected.admitter = true
  })
  invitee.on('connected', () => {
    log.connected.invitee = true
  })
  invitee.on('joined', () => {
    log.joined += 1
  })

  admitter.start()
  invitee.start()

  return {
    admitter,
    invitee,
    wire,
    log,
    injectFromInvitee,

    /** Resolves once both sides report `connected`. */
    async bothConnected() {
      return waitUntil(() => log.connected.admitter && log.connected.invitee)
    },

    /** Resolves with the first local error one side reported. */
    async firstLocalError(side: 'admitter' | 'invitee') {
      await waitUntil(() => log.localErrors[side].length > 0)
      return log.localErrors[side][0]
    },

    stop() {
      admitter.stop(false)
      invitee.stop(false)
    },
  }
}

/** A promise the test resolves or rejects by hand, counting how often the hook was called. */
const deferred = () => {
  let resolve!: () => void
  let reject!: (error: unknown) => void
  const promise = new Promise<void>((res, rej) => {
    resolve = res
    reject = rej
  })
  const gate = {
    calls: 0,
    resolve,
    reject,
    get promise() {
      gate.calls += 1
      return promise
    },
  }
  return gate
}

/** Effective (conflict-resolution-surviving) admissions registering `userId`. */
const effectiveAdmissions = (team: Team, userId: string) =>
  getSequence(team.graph, membershipResolver).filter(
    link =>
      !link.isInvalid &&
      link.body.type === 'ADMIT_MEMBER' &&
      link.body.payload.claim.memberKeys.name === userId
  )

const waitUntil = async (predicate: () => boolean, timeoutMs = 20_000) => {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for a condition')
    // eslint-disable-next-line no-await-in-loop -- polling is the point
    await pause(5)
  }
}
