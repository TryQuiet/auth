import { merge } from '@localfirst/crdx'
import { signatures } from '@localfirst/crypto'
import { assert, eventPromise } from '@localfirst/shared'
import type { ConnectionMessage } from 'connection/message.js'
import { createInvitationAcceptance } from 'connection/invitationAcceptance.js'
import type {
  Context,
  InviteeIdentityClaim,
  InviteeDeviceContext,
  InviteeMemberContext,
  MemberContext,
} from 'connection/types.js'
import type { DeviceWithSecrets } from 'device/index.js'
import { redactDevice, redactFirstUseDevice } from 'device/index.js'
import { createPossessionProof, generateProof } from 'invitation/index.js'
import { pack, unpack } from 'msgpackr'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { Team } from 'team/Team.js'
import type { TeamGraph } from 'team/types.js'
import { deriveUserId } from 'util/userId.js'
import { joinTestChannel, memberClaim, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { NumberedMessage } from '../MessageQueue.js'
import { memberAdmission } from '../../team/test/helpers.js'

type AcceptanceMessage = Extract<ConnectionMessage, { type: 'ACCEPT_INVITATION' }>
type AcceptancePayload = AcceptanceMessage['payload']
type Rewrite = (payload: AcceptancePayload, inviteeClaim: InviteeIdentityClaim) => AcceptancePayload

/**
 * End-to-end tests of how an invitee validates the welcome (ACCEPT_INVITATION) — the message that
 * hands them the team graph and keyring after they present proof of invitation.
 *
 * Threat model: an invitee knows only what came over the side channel — the secret invitation seed
 * and the expected team id — plus this connection's own claim and nonces. The acceptor is
 * untrusted: the seed is a bearer secret, so anyone who learns it (the inviter necessarily knows
 * it, and it may leak) can encrypt a well-formed welcome. The invitee must therefore validate that
 * the graph they receive is the expected team AND that it admits them, with exactly the identity
 * they claimed, via exactly the invitation and handshake they redeemed.
 *
 * Method: every test runs a complete, real handshake in which both peers behave honestly, except
 * that `RewriteAcceptanceChannel` replaces the single ACCEPT_INVITATION message with an
 * attacker-constructed one (built with the production `createInvitationAcceptance`, so it is
 * well-formed and correctly bound to the live transcript — only its *content* is adversarial).
 * Several attacks are given more power than a real attacker has (e.g. graphs only an admin could
 * sign) in order to isolate a single validation rule and prove that rule alone rejects them.
 * Where the rejection reason matters, the test pins the invitee's error type, which identifies the
 * check that fired: ACCEPTANCE_INVALID = envelope authentication, JOINED_WRONG_TEAM = root pin,
 * INVITATION_PROOF_INVALID = sender not active in the delivered graph, ADMIT_MEMBER_LINK_MISSING =
 * no exact effective admission or wrong final identity.
 *
 * Not covered here: tampering by a party who does NOT know the seed (defeated by authenticated
 * encryption — see invitationAcceptance.test.ts, which pins the wire format), attacks on the sync
 * that happens after joining, and the membership resolver's own ordering/invalidations (which have
 * their own suites; one representative resolver interaction is tested below).
 */
describe('invitee validation of the welcome (ACCEPT_INVITATION)', () => {
  // Positive control: with an honest acceptor, both invitation kinds still work. Every rejection
  // test below is only meaningful because this baseline passes with the same helpers.
  it('admits an honest member invitee and an honest device invitee', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const memberInvite = alice.team.inviteMember()
    const member = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: {
        user: bob.user,
        device: bob.device,
        invitationSeed: memberInvite.seed,
        expectedTeamId: memberInvite.teamId,
      },
    })
    expect(member.outcome.kind).toBe('joined')

    const { bob: laptop } = setup('bob')
    const deviceInvite = laptop.team.inviteDevice()
    const device = await connectInvitee({
      acceptor: laptop.connectionContext,
      invitee: {
        userName: laptop.userName,
        device: laptop.phone!,
        invitationSeed: deviceInvite.seed,
        expectedTeamId: deviceInvite.teamId,
      },
    })
    expect(device.outcome.kind).toBe('joined')
  })

  // The connection must send the welcome exactly once, and only in the encrypted v3 envelope.
  // Counting on the wire guards against a duplicate send or a residual plaintext/legacy-format
  // path that an attacker could trigger as a downgrade.
  it('sends exactly one welcome per handshake, always in the encrypted v3 envelope', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
    })

    expect(result.channel.acceptanceCount).toBe(1)
    expect(result.channel.acceptance).toHaveProperty('version', 3)
    expect(result.channel.acceptance).toHaveProperty('encryptedAcceptance', expect.any(Uint8Array))
  })

  // A welcome whose ciphertext fails authentication must be rejected as ACCEPTANCE_INVALID — the
  // envelope-authentication error, produced before the enclosed graph is ever deserialized. The
  // distinct error type is the observable proof of that ordering: unauthenticated bytes never
  // reach graph parsing or validation. (One byte flip stands in for all corruptions; the AEAD
  // guarantee itself is exercised more broadly in invitationAcceptance.test.ts.)
  it('rejects a tampered welcome at decryption, before any graph parsing', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite(payload) {
        const encryptedAcceptance = payload.encryptedAcceptance.slice()
        const index = Math.floor(encryptedAcceptance.length / 2)
        const originalByte = encryptedAcceptance[index]
        encryptedAcceptance[index] = originalByte % 2 === 0 ? originalByte + 1 : originalByte - 1
        return { ...payload, encryptedAcceptance }
      },
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ACCEPTANCE_INVALID' },
    })
  })

  // Being present in the team is not the same as having been admitted. Here the acceptor's graph
  // contains the invitee as a member — added through a plain admin ADD_MEMBER, so the graph is
  // perfectly valid and a naive "am I in the team now?" check would accept it. But no ADMIT link
  // consumed this invitation, so the invitee has no evidence their invitation — rather than the
  // acceptor's say-so — is what admitted them. The exact-admission rule must reject.
  it('rejects a graph that contains the invitee as a member but has no admission for them', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.addForTesting(bob.user, [], redactDevice(bob.device))

    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite: acceptanceFrom(spoof, alice.device),
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // The evil-twin team. An invitation id is derived from the seed alone, so Mallory — who learned
  // the seed — can create the same invitation on a team SHE founded and then run a completely
  // honest acceptor: valid graph, valid admission of the invitee's live proof and claim. Nothing
  // about the admission distinguishes her team from the real one; the only tell is the graph's
  // root hash. This is why the invitee carries expectedTeamId out of band alongside the seed, and
  // this test pins that the root check alone (JOINED_WRONG_TEAM) stops the attack.
  it('rejects an internally valid impostor team hosting the same invitation seed', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const { mallory } = setup('mallory')
    mallory.team.inviteMember({ seed })

    const result = await connectInvitee({
      acceptor: mallory.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'JOINED_WRONG_TEAM' },
    })
  })

  // The seed is a bearer secret, so a well-formed welcome proves nothing about who sent it. The
  // sender check ties the welcome to a device that is *active in the delivered graph itself*: the
  // (encrypted, tamper-proof) acceptorDeviceId must match the outer sender fields, and that
  // device's registered encryption key must be the key the ciphertext authenticates. Here the
  // attacker is handed everything else — the real graph extended with a valid admission of the
  // live claim — and the welcome is sent from Eve's device, which the team never registered. Only
  // the sender check can reject this, so it is proven load-bearing on its own. In practice this
  // stops a seed thief (who is not an active member) from playing acceptor.
  it('rejects a welcome sent by a device the delivered graph does not register', async () => {
    const { alice, bob, eve } = setup(
      'alice',
      { user: 'bob', member: false },
      { user: 'eve', member: false }
    )
    const { seed, teamId } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite(payload, inviteeClaim) {
        // Admit the live claim so every graph and admission check passes; only the sender is wrong.
        assert(inviteeClaim.claim.invitationKind === 'member')
        spoof.admitMember(
          inviteeClaim.proofOfInvitation,
          inviteeClaim.claim,
          inviteeClaim.possessionProof
        )
        return acceptanceFrom(spoof, eve.device)(payload, inviteeClaim)
      },
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'INVITATION_PROOF_INVALID' },
    })
  })

  // The same identity can legitimately hold admissions under several invitations (people do get
  // re-invited). Here Bob redeems invitation #2, but the acceptor's graph admits him only under
  // invitation #1 — a real, valid admission of exactly his identity, just not the redemption
  // happening on this connection. Final state therefore looks perfect; only the provenance rule —
  // the admission must reference THIS invitation and embed THIS handshake's proof — rejects it.
  // Accepting would let an acceptor pretend to consume an invitation it never consumed.
  it('rejects an admission that consumed a different invitation than the one being redeemed', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const first = alice.team.inviteMember()
    const second = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(first.seed, bob))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: {
        user: bob.user,
        device: bob.device,
        invitationSeed: second.seed,
        expectedTeamId: second.teamId,
      },
      rewrite: acceptanceFrom(spoof, alice.device),
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // Same invitation, same identity — but the ADMIT link embeds a proof whose nonces belong to some
  // other handshake (memberAdmission generates fresh random nonces). That is what a replay looks
  // like: an acceptor re-serving a graph in which this invitee was admitted during an earlier
  // session instead of admitting the live one. The proof-equality rule binds the admission to this
  // connection's nonces, making each admission usable for exactly one handshake.
  it('rejects a replayed admission from a different handshake of the same invitation', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(seed, bob))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite: acceptanceFrom(spoof, alice.device),
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // Key substitution. Knowing the seed is enough to sign a proof over ANY claim, so a seed holder
  // can admit an identity with the invitee's name but different keys — hijacking the invitation to
  // register keys the attacker controls. To isolate the key binding, the forged admission reuses
  // the live handshake's nonces (via the rewrite), so it differs from the live claim ONLY in the
  // member keys; the attacker is even granted a valid possession proof, which a real key thief
  // could not produce. The admission must match the invitee's claim byte for byte, and the final
  // state must register exactly the claimed keys — so this is rejected.
  it("rejects an admission that registers different keys under the invitee's invitation", async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite(payload, inviteeClaim) {
        const claim = memberClaim(bob.user, bob.device)
        const changedClaim = {
          ...claim,
          memberKeys: { ...claim.memberKeys, signature: signatures.keyPair().publicKey },
        }
        const { identityNonce, inviteeNonce } = inviteeClaim.proofOfInvitation
        const proof = generateProof({ seed, claim: changedClaim, identityNonce, inviteeNonce })
        const possessionProof = createPossessionProof({
          invitationId: proof.id,
          claim: changedClaim,
          device: bob.device,
        })
        spoof.admitMember(proof, changedClaim, possessionProof)
        return acceptanceFrom(spoof, alice.device)(payload, inviteeClaim)
      },
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // Device invitations are authored by a member for their own devices: the invitation records its
  // author, and joining must register the new device under exactly that user. Here the graph
  // already contains the claimed device — same device id and keys — but registered to a different
  // user, and nothing consumed the invitation. Merely "finding the device in the team" must not
  // count as having joined: that would let an acceptor graft the device onto an account the
  // attacker controls.
  it('rejects a graph in which the claimed device exists but belongs to another user', async () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })
    const { seed, teamId } = bob.team.inviteDevice()
    alice.team.merge(bob.team.graph)
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    const phone = redactFirstUseDevice(bob.phone!)
    const wrongOwnerId = deriveUserId(phone.deviceId)
    const wrongOwner = {
      ...eve.user,
      userId: wrongOwnerId,
      keys: { ...eve.user.keys, name: wrongOwnerId },
    }
    spoof.addForTesting(wrongOwner, [], { ...phone, userId: wrongOwnerId })

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: {
        userName: bob.userName,
        device: bob.phone!,
        invitationSeed: seed,
        expectedTeamId: teamId,
      },
      rewrite: acceptanceFrom(spoof, alice.device),
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // Graphs merge concurrent branches, and the membership resolver decides which links remain in
  // force — in particular, actions by an admin who was concurrently demoted are invalidated. Here
  // Bob (demoted by Alice) invites and admits Charlie on his own branch; after the merge, the raw
  // ADMIT link is present and matches Charlie's live proof exactly, but the resolver voids it.
  // Validation must consult what is effective after resolution, not what is present in the graph —
  // otherwise a demoted or removed admin could still usher people in. This is one representative
  // resolver interaction; the resolver's own ordering rules have their own suites.
  it('rejects an admission that the membership resolver has invalidated', async () => {
    const { alice, bob, charlie } = setup('alice', 'bob', {
      user: 'charlie',
      member: false,
    })
    alice.team.removeMemberRole(bob.userId, 'admin')
    const { seed, teamId } = bob.team.inviteMember()
    bob.team.admitMember(...memberAdmission(seed, charlie))
    const invalidGraph = serializeTeamGraph(merge(alice.team.graph, bob.team.graph) as TeamGraph)
    const invalidKeyring = {
      ...alice.team.teamKeyring(),
      ...bob.team.teamKeyring(),
    }
    const result = await connectInvitee({
      acceptor: bob.connectionContext,
      invitee: {
        user: charlie.user,
        device: charlie.device,
        invitationSeed: seed,
        expectedTeamId: teamId,
      },
      rewrite: acceptanceFromGraph(invalidGraph, invalidKeyring, bob.team, bob.device),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  // An admission is only as good as the state it leaves behind. This graph admits the invitee
  // exactly as claimed — and then removes them. The admission link passes every provenance check;
  // only the final-state rule (the claimed identity must be uniquely active when the graph is
  // fully reduced) rejects. Without it, an invitee could "successfully join" a team they are
  // already off of.
  it('rejects a graph in which the invitee was admitted and then removed', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(seed, bob))
    spoof.remove(bob.userId)

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
      rewrite: acceptanceFrom(spoof, alice.device),
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ADMIT_MEMBER_LINK_MISSING' },
    })
  })

  // Guards against over-strictness. Invitations are multi-use (bounded by expiration), so a graph
  // may legitimately hold several admissions under one invitation id — here Eve was already
  // admitted with the same seed before Bob redeems it. "Exactly one admission" must mean exactly
  // one matching THIS handshake's proof and claim, not one per invitation id; if the rule were
  // keyed on the invitation alone, legitimate reuse would lock every later invitee out.
  it('accepts the matching admission even when the same invitation admitted someone else', async () => {
    const { alice, bob, eve } = setup(
      'alice',
      { user: 'bob', member: false },
      { user: 'eve', member: false }
    )
    const { seed, teamId } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    acceptorTeam.admitMember(...memberAdmission(seed, eve))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed, expectedTeamId: teamId },
    })

    expect(result.outcome.kind).toBe('joined')
    expect(result.invitee.team?.has(bob.userId)).toBe(true)
    expect(result.invitee.team?.has(eve.userId)).toBe(true)
  })
})

/**
 * Passes every message through untouched except ACCEPT_INVITATION, which it hands to `rewrite`
 * along with the invitee's captured identity claim (whose live proof lets attacks bind to the real
 * transcript). Also counts the acceptances it sees, so tests can assert on what actually crossed
 * the wire.
 */
class RewriteAcceptanceChannel extends TestChannel {
  acceptance?: AcceptancePayload
  acceptanceCount = 0
  inviteeClaim?: InviteeIdentityClaim

  constructor(private readonly rewrite?: Rewrite) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numbered = unpack(message) as NumberedMessage<ConnectionMessage>
    if (numbered.type === 'CLAIM_IDENTITY' && 'proofOfInvitation' in numbered.payload) {
      this.inviteeClaim = numbered.payload
    }
    if (numbered.type !== 'ACCEPT_INVITATION') {
      super.write(senderId, message)
      return
    }

    this.acceptanceCount += 1
    this.acceptance = numbered.payload
    assert(this.inviteeClaim, 'Expected invitee claim before invitation acceptance')
    const rewritten = pack({
      ...numbered,
      payload: this.rewrite?.(numbered.payload, this.inviteeClaim) ?? numbered.payload,
    })
    super.write(
      senderId,
      new Uint8Array(rewritten.buffer, rewritten.byteOffset, rewritten.byteLength)
    )
  }
}

type ConnectOptions = {
  acceptor: Context
  invitee: InviteeMemberContext | InviteeDeviceContext
  rewrite?: Rewrite
}

/** Runs one full handshake between an acceptor and an invitee and reports how it ended. */
const connectInvitee = async ({
  acceptor: acceptorContext,
  invitee: inviteeContext,
  rewrite,
}: ConnectOptions) => {
  const channel = new RewriteAcceptanceChannel(rewrite)
  const join = joinTestChannel(channel)
  const acceptor = join(acceptorContext)
  const invitee = join(inviteeContext)
  const outcome = Promise.race([
    eventPromise(invitee, 'joined').then(() => ({ kind: 'joined' as const })),
    eventPromise(invitee, 'localError').then(error => ({
      kind: 'rejected' as const,
      error,
    })),
    eventPromise(invitee, 'remoteError').then(error => ({
      kind: 'rejected' as const,
      error,
    })),
  ])

  acceptor.start()
  invitee.start()
  const settled = await outcome
  acceptor.stop(false)
  invitee.stop(false)
  return { outcome: settled, channel, acceptor, invitee }
}

/**
 * The attacker's working copy: the same graph loaded as a separate Team, so appending spoofed
 * links to it leaves the acceptor's live team untouched.
 */
const cloneTeam = (team: Team, context: Context) =>
  teams.load(team.save(), asMemberContext(context), team.teamKeyring())

/**
 * An acceptor context operating on a pristine clone of the team, so that the live handshake's own
 * admission does not land in the graph the attack is built from.
 */
const withTeam = (context: Context, team: Team): MemberContext => ({
  user: asMemberContext(context).user,
  device: asMemberContext(context).device,
  team,
})

const asMemberContext = (context: Context): MemberContext => context as MemberContext

/**
 * A rewrite that replaces the honest welcome with one built from `team`'s graph, sent by
 * `senderDevice`. It uses the production `createInvitationAcceptance` and the live claim's proof,
 * so the envelope itself is well-formed and correctly transcript-bound — the graph (and possibly
 * the sender) is what's adversarial.
 */
const acceptanceFrom = (team: Team, senderDevice: DeviceWithSecrets): Rewrite =>
  acceptanceFromGraph(team.save(), team.teamKeyring(), team, senderDevice)

const acceptanceFromGraph =
  (
    serializedGraph: Uint8Array,
    teamKeyring: ReturnType<Team['teamKeyring']>,
    invitationTeam: Team,
    senderDevice: DeviceWithSecrets
  ): Rewrite =>
  (_payload, inviteeClaim) => {
    const { proofOfInvitation: proof, claim } = inviteeClaim
    return createInvitationAcceptance({
      invitation: invitationTeam.getInvitation(proof.id),
      proof,
      claim,
      sender: senderDevice,
      serializedGraph,
      teamKeyring,
    })
  }
