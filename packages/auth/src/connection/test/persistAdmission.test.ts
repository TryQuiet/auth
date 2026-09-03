import { getSequence } from '@localfirst/crdx'
import { pause } from '@localfirst/shared'
import { ADMISSION_NOT_PERSISTED, ADMIT_MEMBER_LINK_MISSING } from 'connection/errors.js'
import { findExistingAdmission } from 'connection/existingAdmission.js'
import type { ConnectionMessage } from 'connection/message.js'
import type { InviteeMemberContext, ServerContext } from 'connection/types.js'
import { deriveId, generateProof, type MemberInvitationClaim } from 'invitation/index.js'
import { unpack } from 'msgpackr'
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
        // no graph and no keyring may leave a connection that is no longer running.
        const { alice, inviteeContext } = invite()
        const gate = deferred()

        const { wire, admitter, invitee } = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext,
          async persistAdmission() {
            return gate.promise
          },
        })

        await waitUntil(() => gate.calls === 1)
        admitter.stop()
        invitee.stop()

        gate.resolve()
        await pause(50)
        expect(wire.from(alice.deviceId, 'ACCEPT_INVITATION')).toHaveLength(0)
        expect(invitee.team).toBeUndefined()
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
       * On the admitting side the retry now behaves correctly: it recognizes its own earlier
       * admission of this exact claim, appends nothing (a re-dispatch would throw `The id '…' is
       * already in use` and lock this invitee out of this admitter for good), runs the durable
       * write again — the step that failed — and sends the acceptance.
       *
       * The invitee still refuses that acceptance, and this test pins that. `ProofOfInvitation` is
       * bound to the nonces of the handshake that produced it, and `validateInvitationAcceptance`
       * requires the graph to contain an effective admission carrying *this* handshake's exact
       * proof. The link on the graph carries the first handshake's. So the invitee reports
       * ADMIT_MEMBER_LINK_MISSING and gets nothing — safe, but it means this particular admitter
       * can never admit this invitee again until its team is rebuilt from durable storage (the
       * test above). Closing that gap means changing a rule on the invitee side, which is a
       * separate decision; see the notes in connection/existingAdmission.ts.
       */
      it('re-runs the durable write instead of throwing when the admission is already in memory', async () => {
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
        first.stop()

        expect(alice.team.has(charlie.userId)).toBe(true)

        const second = connectInvitee({
          admitterContext: alice.connectionContext,
          inviteeContext: retryContext(inviteeContext),
          async persistAdmission(team: Team) {
            persisted.push(team)
          },
        })

        // The retry gets as far as a persisted admission and an acceptance on the wire...
        await waitUntil(() => second.wire.from(alice.deviceId, 'ACCEPT_INVITATION').length === 1)
        expect(persisted).toHaveLength(1)
        expect(persisted[0].has(charlie.userId)).toBe(true)

        // ...having appended nothing: the identity is registered exactly once.
        expect(effectiveAdmissions(alice.team, charlie.userId)).toHaveLength(1)

        // ...and the invitee declines it, because the admission on the graph belongs to the
        // earlier handshake.
        expect(await second.firstLocalError('invitee')).toBe(ADMIT_MEMBER_LINK_MISSING)
        expect(second.invitee.team).toBeUndefined()
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
 */
const retryContext = (context: InviteeMemberContext): InviteeMemberContext => ({ ...context })

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
  persistAdmission?: (team: Team) => Promise<void>
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
