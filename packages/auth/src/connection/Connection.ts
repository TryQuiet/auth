/* eslint-disable object-shorthand */
import { EventEmitter } from '@herbcaudill/eventemitter42'
import type { DecryptFnParams } from '@localfirst/crdx'
import {
  generateMessage,
  headsAreEqual,
  initSyncState,
  receiveMessage,
  redactKeys,
} from '@localfirst/crdx'
import {
  asymmetric,
  base58,
  randomKey,
  randomKeyBytes,
  symmetric,
  type Base58,
  type Hash,
} from '@localfirst/crypto'
import { assert, debug, Logger, SharedLogger } from '@localfirst/shared'
import { deriveSharedKey } from 'connection/deriveSharedKey.js'
import {
  DEVICE_REMOVED,
  DEVICE_UNKNOWN,
  ENCRYPTION_FAILURE,
  IDENTITY_PROOF_INVALID,
  INVITATION_PROOF_INVALID,
  JOINED_WRONG_TEAM,
  MEMBER_REMOVED,
  NEITHER_IS_MEMBER,
  SERVER_REMOVED,
  SERVER_UNKNOWN,
  TIMEOUT,
  createErrorMessage,
  type ConnectionErrorType,
  UNHANDLED,
  ADMIT_MEMBER_LINK_MISSING,
} from 'connection/errors.js'
import { getDeviceUserFromState } from 'connection/getDeviceUserFromGraph.js'
import * as identity from 'connection/identity.js'
import type { ConnectionMessage, DisconnectMessage } from 'connection/message.js'
import { redactDevice, redactFirstUseDevice, type DeviceWithSecrets } from 'device/index.js'
import * as invitations from 'invitation/index.js'
import { pack, unpack } from 'msgpackr'
import { castServer } from 'server/castServer.js'
import { getTeamState } from 'team/getTeamState.js'
import { Team, decryptTeamGraph, type TeamAction, type TeamContext } from 'team/index.js'
import * as select from 'team/selectors/index.js'
import { arraysAreEqual } from 'util/arraysAreEqual.js'
import { KeyType } from 'util/index.js'
import { and, assertEvent, assign, createActor, not, setup } from 'xstate'
import { MessageQueue, type NumberedMessage } from './MessageQueue.js'
import {
  extendServerContext,
  getUserName,
  ourLockboxKeys,
  ourSigningKeys,
  stateSummary,
} from './helpers.js'
import type { ConnectionContext, ConnectionEvents, Context, IdentityClaim } from './types.js'
import {
  isInviteeClaim,
  isInviteeContext,
  isInviteeDeviceContext,
  isInviteeMemberClaim,
  isInviteeMemberContext,
  isMemberClaim,
  isMemberContext,
  isServerClaim,
  isServerContext,
} from './types.js'

/** The role a peer is put in on admission, if the team defines it. See `maybeGrantMemberRole`. */
const MEMBER_ROLE = 'member'

/*

HOW TO READ THIS FILE

First of all I know this class is an abomination with literally seventeen billion lines of code in
the constructor alone, but before you come at me with pitchforks you should know that @davidkpiano
himself told me it's OK. So

https://github.com/statelyai/xstate/discussions/4783#discussioncomment-8673350

The bulk of this class is an XState state machine. It's instantiated in the constructor. It looks
something like this:

```ts
const machine = setup({
  types: {...},
  actions: {
    // ... a bunch of action handlers here
  },
  guards: {
    // ... a bunch of guard functions here
}).createMachine({
  //... the state machine definition, which refers back to the actions and guards by name
})
```

To understand the way this flows, the best place to start is the state machine definition passed to
`createMachine`.

You can also visualize this machine in the Stately visualizer - here's a link that's current at time
of writing this:
https://stately.ai/registry/editor/69889811-5f81-4d58-8ef1-f6f3d99fb9ee?machineId=989039f7-631c-4021-a9da-d5f6912dcb03

*/

/**
 * Wraps a state machine (using [XState](https://xstate.js.org/docs/)) that
 * implements the connection protocol.
 */
export class Connection extends EventEmitter<ConnectionEvents> {
  readonly #machine
  readonly #messageQueue: MessageQueue<ConnectionMessage>
  #started = false
  private readonly logger: Logger

  constructor({ sendMessage, context, createLogger }: ConnectionParams) {
    super()

    const username = getUserName(context)
    const loggerModuleName = `auth:connection:${username}`
    let sharedLogger: SharedLogger | undefined
    if (createLogger != null) {
      sharedLogger = createLogger(loggerModuleName)
    }

    this.logger = new Logger({
      moduleName: loggerModuleName,
      sharedLogger,
      extendSharedLogger: false,
    })
    this.#messageQueue = this.#initializeMessageQueue(sendMessage, this.logger, username)

    // A server participates in the key hierarchy as a member, so give it a member projection here
    // rather than special-casing it everywhere downstream.
    const baseContext = isServerContext(context) ? extendServerContext(context) : context

    // Each peer picks a nonce for the identity claim it's about to request, and one for the claim
    // it might present. An invitation proof is bound to both, so it can't be replayed on another
    // connection — which is why the acceptor's nonce has to travel with REQUEST_IDENTITY.
    const initialContext: ConnectionContext = {
      ...baseContext,
      acceptorNonce: randomKey() as Base58,
      inviteeNonce: randomKey() as Base58,
    }

    const machine = setup({
      types: {
        context: {} as ConnectionContext,
        events: {} as ConnectionMessage,
      },

      // ******* ACTIONS
      // these are referred to by name in the state machine definition

      actions: {
        // IDENTITY CLAIMS

        requestIdentityClaim: ({ context }) => {
          this.logger.debug('requesting identity claim')
          this.#queueMessage('REQUEST_IDENTITY', { acceptorNonce: context.acceptorNonce })
        },

        sendIdentityClaim: assign(({ context, event }) => {
          assertEvent(event, 'REQUEST_IDENTITY')
          this.logger.debug('sending identity claim')
          const { acceptorNonce } = event.payload

          /**
           * An invitee's claim is the identity it's asking to have registered, plus two proofs:
           * that it knows the invitation seed, and that it holds the keys in the claim. Only the
           * second is unforgeable by the inviter, so both are needed. Both are signed over the
           * exact claim object we send, and the invitation proof also over both nonces.
           */
          const inviteeClaim = (claim: invitations.InvitationClaim): IdentityClaim => {
            assert(context.invitationSeed)
            assert(context.device)
            const proofOfInvitation = invitations.generateProof({
              seed: context.invitationSeed,
              claim,
              acceptorNonce,
              inviteeNonce: context.inviteeNonce,
            })
            const possessionProof = invitations.createPossessionProof({
              invitationId: proofOfInvitation.id,
              claim,
              device: context.device,
            })
            return { proofOfInvitation, claim, possessionProof }
          }

          const createIdentityClaim = (context: ConnectionContext): IdentityClaim => {
            if (isServerContext(context)) {
              // I'm a server; my identity is my serverId, never my host
              return { serverId: context.server.serverId }
            }
            if (isMemberContext(context)) {
              // I'm already a member
              return { deviceId: context.device.deviceId }
            }
            if (isInviteeMemberContext(context)) {
              // I'm a new user and I have an invitation
              const { userName, keys } = context.user
              return inviteeClaim({
                invitationKind: 'member',
                userName,
                memberKeys: redactKeys(keys),
                device: redactDevice(context.device),
              })
            }
            if (isInviteeDeviceContext(context)) {
              // I'm a new device for an existing user and I have an invitation. My claim carries no
              // owner: that comes from the invitation record on the team graph.
              return inviteeClaim({
                invitationKind: 'device',
                device: redactFirstUseDevice(context.device),
              })
            }
            // ignore coverage - that should have been exhaustive
            throw new Error('Invalid context')
          }

          const ourIdentityClaim = createIdentityClaim(context)
          this.#queueMessage('CLAIM_IDENTITY', ourIdentityClaim)

          return { ourIdentityClaim }
        }),

        receiveIdentityClaim: assign(({ event }) => {
          this.logger.debug('received identity claim')
          assertEvent(event, 'CLAIM_IDENTITY')
          const identityClaim = event.payload
          const theirDevice = isInviteeClaim(identityClaim) ? identityClaim.claim.device : undefined
          return { theirIdentityClaim: identityClaim, theirDevice }
        }),

        // INVITATIONS

        acceptInvitation: assign(({ context }) => {
          this.logger.debug('accepting invitation')
          // Admit them to the team
          const { team, theirIdentityClaim } = context

          assert(team)
          assert(theirIdentityClaim)
          assert(isInviteeClaim(theirIdentityClaim))

          const { proofOfInvitation, claim, possessionProof } = theirIdentityClaim

          const admit = () => {
            if (isInviteeMemberClaim(theirIdentityClaim)) {
              this.logger.debug('handling member invite action')
              // New member, along with the first device they'll sign links with
              team.admitMember(proofOfInvitation, theirIdentityClaim.claim, possessionProof)
              const userId = theirIdentityClaim.claim.memberKeys.name
              this.#maybeGrantMemberRole(context, userId)
              return team.members(userId)
            } else {
              this.logger.debug('handling device invite action')
              // New device for an existing member
              team.admitDevice(
                proofOfInvitation,
                claim as invitations.DeviceInvitationClaim,
                possessionProof
              )
              const { userId } = team.memberByDeviceId(claim.device.deviceId)
              return team.members(userId)
            }
          }

          let peer
          try {
            peer = admit()
          } catch (error) {
            // The invitation checked out, but the identity it presented can't be registered — a
            // duplicate id, say. Report it rather than letting the throw kill the machine.
            this.logger.error('failed to admit the invitee', error)
            return this.#fail(INVITATION_PROOF_INVALID)
          }

          // Welcome them by sending the team's graph, so they can reconstruct team membership state
          this.#queueMessage('ACCEPT_INVITATION', {
            serializedGraph: team.save(),
            teamKeyring: team.teamKeyring(),
          })

          return { peer }
        }),

        /**
         * Derives team state from the graph we've been sent, so the guards that decide whether to
         * join it are simple reads. A graph that doesn't deserialize or doesn't validate leaves
         * `state` undefined rather than throwing out of a guard and killing the machine.
         */
        receiveInvitationAcceptance: assign(({ event }) => {
          assertEvent(event, 'ACCEPT_INVITATION')
          this.logger.debug('received invitation acceptance')
          const { serializedGraph, teamKeyring } = event.payload
          try {
            const state = getTeamState(serializedGraph, teamKeyring, this.logger)
            return { acceptance: { serializedGraph, teamKeyring, state } }
          } catch (error) {
            this.logger.error('the team graph we were sent is not valid', error)
            return { acceptance: { serializedGraph, teamKeyring } }
          }
        }),

        joinTeam: assign(({ context }) => {
          this.logger.debug('joining team post invitation acceptance')
          const { acceptance, invitationSeed } = context
          assert(acceptance?.state)
          assert(invitationSeed)
          assert(context.device)
          const { serializedGraph, teamKeyring, state } = acceptance

          const user =
            context.user ??
            // If we're joining as a new device for an existing member, we won't have a user object
            // yet, so we need to get those from the graph. We use the invitation seed to generate
            // the starter keys for the new device. We can use these to unlock a lockbox on the team
            // graph that contains our user keys.
            getDeviceUserFromState({ state, invitationSeed })

          // Our device was registered by the admission itself; from here on it belongs to that user.
          const device = { ...context.device, userId: user.userId } as DeviceWithSecrets

          // When admitting us, our peer added our user to the team graph. We've been given the
          // serialized and encrypted graph, and the team keyring. We can now decrypt the graph and
          // reconstruct the team in order to join it.
          const team = new Team({
            source: serializedGraph,
            context: { user, device },
            teamKeyring,
            sharedLogger: this.logger.sharedLogger,
          })

          // Our first act as a registered signer is to post a lockbox holding our user keys for our
          // device, so we can rehydrate the team on our own later. This has to happen before we
          // merge anything, since merging re-decrypts the incoming graph with our device keys.
          team.join(teamKeyring)
          this.emit('joined', { team, user, teamKeyring })
          return { user, device, team }
        }),

        // AUTHENTICATION

        challengeIdentity: assign(({ context }) => {
          this.logger.debug('challenging identity claim')
          const { team, theirIdentityClaim } = context
          assert(team) // If we're not on the team yet, we don't have a way of knowing if the peer is
          assert(theirIdentityClaim)

          // A peer authenticates as the signer it authors links with: a device with its device
          // keys, or a server with its immutable identity keys.
          if (isServerClaim(theirIdentityClaim)) {
            const { serverId } = theirIdentityClaim
            const peer = castServer.toMember(team.servers(serverId, { includeRemoved: true }))
            this.logger.debug('Found the following server information', serverId)
            this.logger.extend(peer.userName)

            const challenge = identity.challenge({ type: KeyType.SERVER_IDENTITY, name: serverId })
            this.#queueMessage('CHALLENGE_IDENTITY', { challenge })
            return { peer, challenge }
          }

          assert(isMemberClaim(theirIdentityClaim))

          // look up their device and user info on the team
          const { deviceId } = theirIdentityClaim
          const theirDevice = team.device(deviceId, { includeRemoved: true })
          const peer = team.memberByDeviceId(deviceId, { includeRemoved: true })
          this.logger.debug(
            'Found the following device and member information',
            theirDevice.deviceId,
            peer.userId
          )

          // we now have a user name so add that to the logger
          this.logger.extend(peer.userName)

          // send them an identity challenge
          const challenge = identity.challenge({ type: KeyType.DEVICE, name: deviceId })
          this.#queueMessage('CHALLENGE_IDENTITY', { challenge })

          // record their identity info and the challenge in context
          return { theirDevice, peer, challenge }
        }),

        proveIdentity: ({ context, event }) => {
          assertEvent(event, 'CHALLENGE_IDENTITY')
          this.logger.debug('proving identity in response to challenge')
          const { challenge } = event.payload
          const proof = identity.prove(challenge, ourSigningKeys(context))
          this.#queueMessage('PROVE_IDENTITY', { challenge, proof })
        },

        acceptIdentity: ({ context, event }) => {
          assertEvent(event, 'PROVE_IDENTITY')
          this.logger.debug('accepting identity claim')
          assert(context.team)
          assert(context.peer)

          this.#maybeGrantMemberRole(context, context.peer.userId)
          this.#queueMessage('ACCEPT_IDENTITY')
        },

        // SYNCHRONIZATION

        listenForTeamUpdates: ({ context }) => {
          assert(context.team)
          this.logger.debug('starting event listener for chain updates')
          context.team.on('updated', ({ head }: { head: Hash[] }) => {
            if (this.#machine.getSnapshot().status !== 'done') {
              this.#machine.send({ type: 'LOCAL_UPDATE', payload: { head } }) // Send update event to local machine
            }
            this.emit('updated', head)
          })
        },

        sendSyncMessage: assign(({ context }) => {
          assert(context.team)
          this.logger.debug('processing outgoing sync message')
          const previousSyncState = context.syncState ?? initSyncState()

          const [syncState, syncMessage] = generateMessage(context.team.graph, previousSyncState)

          // Undefined message means we're already synced
          if (syncMessage) {
            this.logger.debug('sending sync message', syncMessage.head)
            this.#queueMessage('SYNC', syncMessage)
          } else {
            this.logger.debug('no sync message to send')
          }

          return { syncState }
        }),

        receiveSyncMessage: assign(({ context, event }) => {
          assertEvent(event, 'SYNC')
          this.logger.debug('processing incoming sync message')
          const syncMessage = event.payload
          const { syncState: prevSyncState = initSyncState(), team } = context

          assert(team)
          // The whole keyring, not just the current generation: links written before a key
          // rotation — the root, always — can only be opened with the generation they were
          // written under.
          const teamKeyring = team.teamKeyring()
          const deviceKeys = ourLockboxKeys(context)

          // handle errors here
          const decrypt = ({ encryptedGraph, keys }: DecryptFnParams<TeamAction, TeamContext>) =>
            decryptTeamGraph({ encryptedGraph, teamKeys: keys, deviceKeys })

          const [newChain, syncState] = receiveMessage(
            team.graph,
            prevSyncState,
            syncMessage,
            teamKeyring,
            decrypt,
            this.logger
          )

          if (headsAreEqual(newChain.head, team.graph.head)) {
            // console.log(`${context!.user!.userName}: Sync message received but heads were equal`)
            // nothing changed
            return { syncState }
          } else {
            // console.log(`${context!.user!.userName}: Sync message received and merging`)
            this.emit('updated', newChain.head)
            return { team: team.merge(newChain), syncState }
          }
        }),

        // SHARED SECRET NEGOTIATION

        sendSeed: assign(({ context }) => {
          this.logger.debug('sending encrypted seed')
          const { user, peer, seed = randomKeyBytes() } = context

          const recipientPublicKey = peer!.keys.encryption
          const senderSecretKey = user!.keys.encryption.secretKey

          this.logger.debug(`encrypting seed with key ${recipientPublicKey}`)
          const encryptedSeed = asymmetric.encryptBytes({
            secret: seed,
            recipientPublicKey,
            senderSecretKey,
          })

          this.#queueMessage('SEED', { encryptedSeed })
          return { seed }
        }),

        deriveSharedKey: assign(({ context, event }) => {
          assertEvent(event, 'SEED')
          this.logger.debug('deriving shared key')
          const { encryptedSeed } = event.payload
          const { user, peer } = context
          const seed = context.seed!
          const cipher = encryptedSeed
          const senderPublicKey = peer!.keys.encryption
          const recipientSecretKey = user!.keys.encryption.secretKey

          // decrypt the seed they sent. Anything the peer sends that we can't open means we don't
          // share a secure channel with them, whatever the underlying cipher had to say about it.
          let theirSeed: unknown
          try {
            theirSeed = asymmetric.decryptBytes({ cipher, senderPublicKey, recipientSecretKey })
          } catch (error) {
            this.logger.error(`failed to decrypt seed using public key ${senderPublicKey}`, error)
            return this.#fail(ENCRYPTION_FAILURE)
          }

          this.emit('connectionSecured')
          // With the two keys, we derive a shared key
          return { sessionKey: deriveSharedKey(seed, theirSeed as Uint8Array) }
        }),

        // ENCRYPTED COMMUNICATION

        receiveEncryptedMessage: ({ context, event }) => {
          assertEvent(event, 'ENCRYPTED_MESSAGE')
          this.logger.debug('processing incoming encrypted message')
          const sessionKey = context.sessionKey!
          const encryptedMessage = event.payload

          try {
            const decryptedMessage = symmetric.decryptBytes(encryptedMessage, sessionKey)
            this.emit('message', decryptedMessage)
          } catch (error) {
            // A message we can't open means the session key isn't shared after all
            this.logger.error(
              `failed to decrypt message using session key ${base58.encode(sessionKey)}`,
              error
            )
            return this.#fail(ENCRYPTION_FAILURE)
          }
        },

        // FAILURE

        fail: assign((_, { error }: { error: ConnectionErrorType }) => {
          this.logger.error('failure case', error)
          return this.#fail(error)
        }),

        receiveError: assign(({ event }) => {
          assertEvent(event, 'ERROR')
          const error = event.payload
          this.logger.error('receiveError', error)
          this.emit('remoteError', error)
          return { error }
        }),

        sendError: assign(({ event }) => {
          assertEvent(event, 'LOCAL_ERROR')
          const error = event.payload
          this.logger.error('sendError', error)
          this.#messageQueue.send(createErrorMessage(error.type, 'REMOTE'))
          this.emit('localError', error)
          return { error }
        }),

        // EVENTS FOR EXTERNAL LISTENERS

        onConnected: context => {
          this.logger.debug('emitting connected event')
          this.emit('connected')
          // this.#machine.send({ type: 'SYNC', payload: { head } }) // Send update event to local machine
        },
        onDisconnected: ({ event }) => {
          this.logger.debug('emitting disconnected event')
          this.emit('disconnected', event)
        },
      },

      // ******* GUARDS
      // these are referred to by name in the state machine definition

      guards: {
        theySentIdentityClaim: ({ context }) => {
          this.logger.debug('GUARD: checking for peer identity claim')
          const result = context.theirIdentityClaim !== undefined
          this.logger.debug('GUARD: peer identity claim exists?', result)
          return result
        },
        weSentIdentityClaim: ({ context }) => {
          this.logger.debug('GUARD: checking for own identity claim')
          const result = context.ourIdentityClaim !== undefined
          this.logger.debug('GUARD: own identity claim exists?', result)
          return result
        },
        bothSentIdentityClaim: and(['theySentIdentityClaim', 'weSentIdentityClaim']),

        weHaveInvitation: ({ context }) => {
          this.logger.debug('GUARD: checking for invitation on context')
          const result = isInviteeContext(context)
          this.logger.debug('GUARD: is invitee context?', result)
          return result
        },
        theyHaveInvitation: ({ context }) => {
          this.logger.debug('GUARD: checking for invitation on peer identity claim')
          const result = isInviteeClaim(context.theirIdentityClaim!)
          this.logger.debug('GUARD: is invitee identity claim?', result)
          return result
        },
        neitherIsMember: and(['weHaveInvitation', 'theyHaveInvitation']),
        invitationIsValid: ({ context }) => {
          this.logger.debug('GUARD: validating invitation')
          const { team, theirIdentityClaim, acceptorNonce } = context
          assert(isInviteeClaim(theirIdentityClaim!))
          const { proofOfInvitation, claim, possessionProof } = theirIdentityClaim

          // The proof has to have been made for *this* handshake, or an eavesdropper could replay
          // one they saw on another connection.
          if (proofOfInvitation.acceptorNonce !== acceptorNonce) {
            this.logger.error('the invitation proof was made for a different handshake')
            return false
          }

          const result = team!.validateInvitation(proofOfInvitation, claim, possessionProof).isValid
          this.logger.debug('GUARD: is invitation valid?', result)
          return result
        },

        inviteeDeviceWasRemoved: ({ context }) => {
          const { team, theirIdentityClaim } = context
          assert(isInviteeClaim(theirIdentityClaim!))
          // A removed device is tombstoned forever: its id can never be registered again, so an
          // invitation doesn't help it back onto the team.
          const result = team!.deviceWasRemoved(theirIdentityClaim.claim.device.deviceId)
          this.logger.debug('GUARD: was the invitee device removed?', result)
          return result
        },

        inviteeMemberWasRemoved: ({ context }) => {
          const { team, theirIdentityClaim } = context
          assert(isInviteeClaim(theirIdentityClaim!))
          if (!isInviteeMemberClaim(theirIdentityClaim)) return false
          const result = team!.memberWasRemoved(theirIdentityClaim.claim.memberKeys.name)
          this.logger.debug('GUARD: was the invitee member removed?', result)
          return result
        },

        acceptanceIsValid: ({ context }) => {
          this.logger.debug('GUARD: checking that the team graph we were sent is valid')
          const result = context.acceptance?.state !== undefined
          this.logger.debug('GUARD: is the team graph valid?', result)
          return result
        },

        joinedTheWrongTeam: ({ context }) => {
          this.logger.debug('GUARD: validating invitation against team')
          const { acceptance, invitationSeed } = context
          assert(acceptance?.state)
          assert(invitationSeed)

          // Make sure my invitation exists on the graph of the team I'm about to join. This check
          // prevents an attack in which a fake team pretends to accept my invitation.
          const result = select.hasInvitation(acceptance.state, invitations.deriveId(invitationSeed))
          this.logger.debug('GUARD: does invitation match team?', result)
          return !result
        },

        weWereAdmitted: ({ context }) => {
          this.logger.debug('GUARD: checking for our admission on the chain')
          const { acceptance, device } = context
          assert(acceptance?.state)
          assert(device)

          // Our device is registered by the very link that admits us — ADMIT_MEMBER registers the
          // member together with their first device, and ADMIT_DEVICE registers the device — so
          // finding our device is what tells us the admission actually happened. This subsumes the
          // separate device-invitation branch from #48c0334: a device invitation admits us via
          // ADMIT_DEVICE, which this same lookup detects.
          let result = false
          try {
            result = select.hasDevice(acceptance.state, device.deviceId)
          } catch (error) {
            // e.g. the id resolves ambiguously in the state they sent us
            this.logger.error('could not look up our device in the graph we were sent', error)
          }
          this.logger.debug('GUARD: were we admitted?', result)
          return result
        },

        peerIsUnknown: ({ context }) => {
          this.logger.debug('GUARD: checking for peer identity on chain')
          const { theirIdentityClaim, team } = context
          assert(theirIdentityClaim)
          // This is only for existing peers (authenticating with an id rather than an invitation)
          if (isServerClaim(theirIdentityClaim)) return false
          assert(isMemberClaim(theirIdentityClaim))
          const deviceMissing = !team!.hasDevice(theirIdentityClaim.deviceId, {
            includeRemoved: true,
          })
          if (deviceMissing) {
            this.logger.error(`Device ${theirIdentityClaim.deviceId} was unknown`)
          }
          return deviceMissing
        },

        peerServerIsUnknown: ({ context }) => {
          const { theirIdentityClaim, team } = context
          assert(theirIdentityClaim)
          if (!isServerClaim(theirIdentityClaim)) return false
          const serverMissing = !team!.hasServer(theirIdentityClaim.serverId, {
            includeRemoved: true,
          })
          if (serverMissing) {
            this.logger.error(`Server ${theirIdentityClaim.serverId} was unknown`)
          }
          return serverMissing
        },

        identityIsValid: ({ context, event }) => {
          assertEvent(event, 'PROVE_IDENTITY')
          this.logger.debug('GUARD: validating peer identity')
          const { challenge, proof } = event.payload
          const result = context.team!.verifyIdentityProof(challenge, proof)
          this.logger.debug('GUARD: peer identity valid?', result)
          return result
        },

        memberWasRemoved: ({ context }) => {
          this.logger.debug('GUARD: ensuring member is not removed')
          const result = context.team!.memberWasRemoved(context.peer!.userId)
          this.logger.debug('GUARD: is member removed?', result)
          return result
        },

        deviceWasRemoved: ({ context }) => {
          this.logger.debug('GUARD: ensuring device is not removed')
          // A server peer has no device, so there's nothing to check
          const result =
            context.theirDevice !== undefined &&
            context.team!.deviceWasRemoved(context.theirDevice.deviceId)
          this.logger.debug('GUARD: is device removed?', result)
          return result
        },

        serverWasRemoved: ({ context }) => {
          this.logger.debug('GUARD: ensuring server is not removed')
          const result = context.team!.serverWasRemoved(context.peer!.userId)
          this.logger.debug('GUARD: is server removed', result)
          return result
        },

        headsAreEqual: ({ context }) => {
          this.logger.debug('GUARD: checking if heads are equal')
          const result = arraysAreEqual(
            context.team!.graph.head, // our head
            context.syncState?.lastCommonHead // last head we had in common with peer
          )
          this.logger.debug('GUARD: are heads equal?', result)
          return result
        },
      },
    }).createMachine({
      context: initialContext as ConnectionContext,

      // ******* STATE MACHINE DEFINITION

      id: 'connection',
      entry: 'requestIdentityClaim',
      initial: 'awaitingIdentityClaim',
      on: {
        REQUEST_IDENTITY: { actions: 'sendIdentityClaim', target: '.awaitingIdentityClaim' },
        // Remote error (sent by peer)
        ERROR: { actions: 'receiveError', target: '#disconnected' },
        // Local error (detected by us, sent to peer)
        LOCAL_ERROR: { actions: 'sendError', target: '#disconnected' },
      },

      states: {
        awaitingIdentityClaim: {
          // Don't respond to a request for an identity claim if we've already sent one
          always: { guard: 'bothSentIdentityClaim', target: 'authenticating' },
          on: { CLAIM_IDENTITY: { actions: 'receiveIdentityClaim' } },
          ...timeout,
        },

        // To authenticate, each peer either presents an invitation (as a new device or as a new
        // member) or a deviceId.
        authenticating: {
          initial: 'checkingInvitations',
          states: {
            // A new member or new device is invited by being given a randomly-generated secret
            // seed. This seed is used to generate a temporary keypair, the public half of which is
            // recorded on the team graph by the device creating the invitation. The invitee can
            // then use the seed to generate the same keypair, and use that to sign a payload that
            // can be verified by anyone on the team.
            checkingInvitations: {
              always: [
                // We can't both present invitations - someone has to be a member
                { guard: 'neitherIsMember', ...fail(NEITHER_IS_MEMBER) },
                // If I have an invitation, wait for acceptance
                { guard: 'weHaveInvitation', target: 'awaitingInvitationAcceptance' },
                // If they have an invitation, validate it
                { guard: 'theyHaveInvitation', target: 'validatingInvitation' },
                // If there are no invitations, we can proceed directly to verifying each other's identity
                { target: '#checkingIdentity' },
              ],
            },

            awaitingInvitationAcceptance: {
              // Wait for them to validate the invitation we included in our identity claim
              on: {
                ACCEPT_INVITATION: {
                  actions: 'receiveInvitationAcceptance',
                  target: 'checkingInvitationAcceptance',
                },
              },
              ...timeout,
            },

            checkingInvitationAcceptance: {
              always: [
                // A graph we can't validate tells us nothing, so treat it like the wrong team
                { guard: not('acceptanceIsValid'), ...fail(JOINED_WRONG_TEAM) },
                // Make sure the team I'm joining is actually the one that invited me
                { guard: 'joinedTheWrongTeam', ...fail(JOINED_WRONG_TEAM) },
                // Make sure we've actually been admitted before we start signing links
                { guard: 'weWereAdmitted', actions: 'joinTeam', target: '#checkingIdentity' },
                fail(ADMIT_MEMBER_LINK_MISSING),
              ],
            },

            validatingInvitation: {
              always: [
                // An identity we've retired can never be registered again, invitation or no
                { guard: 'inviteeDeviceWasRemoved', ...fail(DEVICE_REMOVED) },
                { guard: 'inviteeMemberWasRemoved', ...fail(MEMBER_REMOVED) },
                // If the proof succeeds, add them to the team and send an acceptance message,
                // then proceed to the standard identity claim & challenge process
                {
                  guard: 'invitationIsValid',
                  actions: 'acceptInvitation',
                  target: '#checkingIdentity',
                },
                // If the proof fails, disconnect with error
                fail(INVITATION_PROOF_INVALID),
              ],
            },

            // We use a signature challenge to verify the identity of an existing team member: We
            // send them a payload that includes a random element, they sign it with their private
            // signature key, and we verify it with their public signature key.
            //
            // Note: The signature challenge is probably not sufficient on its own to prove
            // identity; I suspect it can be defeated with a replay attack, in which Eve
            // simultaneously authenticates to Alice as Bob, and to Bob as Alice, using each of them
            // to sign the challenges provided by the other.
            //
            // In practice the session key negotiation process (below) provides much stronger
            // guarantees of authenticity, because it doesn't involve sending a proof that could be
            // replayed; instead it requires all further communication to be encrypted with an
            // independently derived shared secret that can only be calculated by the parties if
            // they have the correct private encryption keys. See
            // https://github.com/local-first-web/auth/discussions/42
            //
            // We considered removing the signature challenge entirely, but it does provide an
            // additional layer of security in the sense that it requires the peer to demonstrate
            // that they have the signature key in addition to the encrypted key.
            checkingIdentity: {
              id: 'checkingIdentity',
              type: 'parallel',
              // Peers mutually authenticate to each other, so we have to complete two 'parallel' processes:
              // 1. prove our identity
              // 2. verify their identity

              states: {
                // 1. prove our identity
                provingMyIdentity: {
                  initial: 'awaitingIdentityChallenge',
                  states: {
                    awaitingIdentityChallenge: {
                      // If we just presented an invitation, they already know who we are
                      always: { guard: 'weHaveInvitation', target: 'done' },
                      on: {
                        // When we receive a challenge, respond with proof
                        CHALLENGE_IDENTITY: {
                          actions: 'proveIdentity',
                          target: 'awaitingIdentityAcceptance',
                        },
                      },
                      ...timeout,
                    },
                    // Wait for a message confirming that they've validated our proof of identity
                    awaitingIdentityAcceptance: {
                      on: { ACCEPT_IDENTITY: { target: 'done' } },
                      ...timeout,
                    },
                    done: { type: 'final' },
                  },
                },

                // 2. verify their identity
                verifyingTheirIdentity: {
                  initial: 'challengingIdentity',

                  states: {
                    // Send a signature challenge
                    challengingIdentity: {
                      always: [
                        // If they just presented an invitation, we already know who they are
                        { guard: 'theyHaveInvitation', target: 'done' },
                        // We received their identity claim in their CLAIM_IDENTITY message. Do we
                        // have a device (or a server) on the team matching their identity claim?
                        { guard: 'peerIsUnknown', ...fail(DEVICE_UNKNOWN) },
                        { guard: 'peerServerIsUnknown', ...fail(SERVER_UNKNOWN) },
                        // Send a challenge.
                        { actions: 'challengeIdentity', target: 'awaitingIdentityProof' },
                      ],
                    },

                    // Then wait for them to respond to the challenge with proof
                    awaitingIdentityProof: {
                      on: {
                        PROVE_IDENTITY: [
                          // If the proof succeeds, send them an acceptance message and continue
                          { guard: 'identityIsValid', actions: 'acceptIdentity', target: 'done' },
                          // If the proof fails, disconnect with error
                          fail(IDENTITY_PROOF_INVALID),
                        ],
                      },
                      ...timeout,
                    },
                    done: { type: 'final' },
                  },
                },
              },
              // Once BOTH processes complete, we continue
              onDone: { target: 'done' },
            },
            done: { type: 'final' },
          },
          onDone: { target: '#negotiating' },
        },

        // Negotiate a session key (shared secret). Alice generates a random seed, asymmetrically
        // encrypts it with her private key and Bob's public key, and sends it to Bob, who decrypts
        // it with his private key and Alice's public key; and vice versa. Both parties then combine
        // the two seeds to derive a shared key.
        negotiating: {
          id: 'negotiating',
          entry: 'sendSeed',
          on: { SEED: { actions: 'deriveSharedKey', target: 'synchronizing' } },
          ...timeout,
        },

        // Synchronize our team graph with the peer
        synchronizing: {
          id: 'sync',
          entry: 'sendSyncMessage',
          always: { guard: 'headsAreEqual', target: 'connected' },
          on: { SYNC: { actions: ['receiveSyncMessage', 'sendSyncMessage'] } },
        },

        // Once we're connected, all we need to do is just keep team graph in sync with our peer,
        // and relay encrypted messages.
        connected: {
          id: 'connected',
          entry: ['onConnected', 'listenForTeamUpdates'],
          always: [
            // If updates to the team graph result in our peer being removed from the team,
            // disconnect
            { guard: 'memberWasRemoved', ...fail(MEMBER_REMOVED) },
            { guard: 'deviceWasRemoved', ...fail(DEVICE_REMOVED) },
            { guard: 'serverWasRemoved', ...fail(SERVER_REMOVED) },
          ],
          on: {
            // If the team graph is modified locally, send them a sync message
            LOCAL_UPDATE: { actions: 'sendSyncMessage' },
            // If they send a sync message, process it
            SYNC: { actions: ['receiveSyncMessage', 'sendSyncMessage'] },
            // Deliver any encrypted messages
            ENCRYPTED_MESSAGE: { actions: 'receiveEncryptedMessage' },
            // If they disconnect we disconnect
            DISCONNECT: '#disconnected',
          },
        },

        // Once we disconnect, no further messages will be sent or received; to reconnect,
        // a new Connection object must be created.
        disconnected: {
          id: 'disconnected',
          always: { actions: 'onDisconnected' },
        },
      },
    })

    // Instantiate the state machine
    this.#machine = createActor(machine)

    // emit and log all transitions
    this.#machine.subscribe({
      next: state => {
        const summary = stateSummary(state.value as string)
        this.emit('change', summary)
        this.logger.debug(`⏩ ${JSON.stringify(state.value, null, 2)} `)
      },
      error: error => {
        // Errors don't survive the logger's formatting, so spell them out
        this.logger.error(
          'Connection encountered an unhandled error',
          error instanceof Error ? `${error.message}\n${error.stack}` : error
        )
        this.#messageQueue.send(createErrorMessage(UNHANDLED, 'REMOTE'))
        this.emit('localError', { type: UNHANDLED, message: 'Unhandled error' })
        this.#fail(UNHANDLED)
      },
    })

    // add automatic logging to all events
    this.emit = (event, ...args) => {
      this.logger.debug(`emit ${event}`)
      return super.emit(event, ...args)
    }
  }

  // PUBLIC API

  /** Starts the state machine. Returns this Connection object. */
  public start = (storedMessages: Uint8Array[] = []) => {
    this.logger.debug('starting')
    this.#machine.start()
    this.#messageQueue.start()
    this.#started = true

    // if incoming messages were received before we existed, queue them up for the machine
    for (const m of storedMessages) this.deliver(m)

    return this
  }

  /** Shuts down and sends a disconnect message to the peer. */
  public stop = (sendPeerDisconnect = true) => {
    if (this.#started && this.#machine.getSnapshot().status !== 'done') {
      const disconnectMessage: DisconnectMessage = { type: 'DISCONNECT' }
      this.#machine.send(disconnectMessage) // Send disconnect event to local machine
      if (sendPeerDisconnect) {
        this.#messageQueue.send(disconnectMessage) // Send disconnect message to peer
      }
    }

    this.removeAllListeners()
    this.#messageQueue.stop()
    this.logger.warn('connection stopped')
    return this
  }

  /**
   * Adds connection messages from the peer to the MessageQueue's incoming message queue, which
   * will pass them to the state machine in order.
   */
  public deliver(serializedMessage: Uint8Array) {
    const message = unpack(serializedMessage) as NumberedMessage<ConnectionMessage>
    this.logger.debug('received message', message)
    this.#messageQueue.receive(message)
  }

  /**
   * Public interface for sending a message from the application to our peer via this connection's
   * encrypted channel. We don't care about the content of this message.
   */
  public send = (message: any) => {
    assert(this._sessionKey, "Can't send encrypted messages until we've finished connecting")
    this.logger.debug('sending message', message)
    const encryptedMessage = symmetric.encryptBytes(message, this._sessionKey)
    this.logger.debug(`encrypted message with session key ${base58.encode(this._sessionKey)}`)
    this.#queueMessage('ENCRYPTED_MESSAGE', encryptedMessage)
  }

  /** Returns the current state of the protocol machine.  */
  get state() {
    assert(this.#started)
    return this.#machine.getSnapshot().value
  }

  // PUBLIC FOR TESTING

  /**
   * Returns the team that the connection's user is a member of. If the user has not yet joined a
   * team, returns undefined.
   */
  get team() {
    return this._context.team
  }

  // PRIVATE

  /**
   * Returns the connection's session key when we are in a connected state. Otherwise, returns
   * `undefined`.
   */
  get _sessionKey() {
    return this._context.sessionKey
  }

  get _context(): ConnectionContext {
    assert(this.#started)
    return this.#machine.getSnapshot().context
  }

  get _started(): boolean {
    return this.#started
  }

  #initializeMessageQueue(
    sendMessage: (message: Uint8Array) => void,
    extendableLogger?: Logger,
    username?: string
  ) {
    // To send messages to our peer, we give them to the ordered message queue, which will deliver
    // them using the `sendMessage` function provided.
    return new MessageQueue<ConnectionMessage>({
      sendMessage: message => {
        this.#logMessage('out', message)
        const serialized = pack(message)
        sendMessage(Uint8Array.from(serialized))
      },
      extendableLogger,
    })
      .on('message', message => {
        this.#logMessage('in', message)
        // Handle requests from the peer to resend messages that they missed
        if (message.type === 'REQUEST_RESEND') {
          const { index } = message.payload
          this.#messageQueue.resend(index)
        } else {
          // Pass other messages from peer to the state machine
          this.#machine.send(message)
        }
      })
      .on('request', index => {
        // Send out requests to resend messages that we missed
        this.#queueMessage('REQUEST_RESEND', { index })
      })
  }

  /**
   * Puts a peer in the team's `member` role, if the team has one.
   *
   * Applications built on this library commonly define a catch-all role that every human member
   * belongs to (Quiet, for one, creates `member` when it creates a team) and expect admission to
   * grant it. Teams that never define the role get nothing: assigning a role that doesn't exist
   * throws, and that throw used to escape into the state machine and kill every connection.
   *
   * Servers are excluded on both sides — a server isn't a member and holds no role keys.
   */
  #maybeGrantMemberRole(context: ConnectionContext, userId: string) {
    const { team, server } = context
    assert(team)
    if (server !== undefined) return
    if (!team.hasRole(MEMBER_ROLE)) return
    if (team.hasServer(userId)) return
    if (team.members(userId).roles?.includes(MEMBER_ROLE)) return

    this.logger.debug(`granting the ${MEMBER_ROLE} role to ${userId}`)
    team.addMemberRole(userId, MEMBER_ROLE)
  }

  /** Force local error state */
  #fail(error: ConnectionErrorType) {
    this.logger.error('error', error)
    const localMessage = createErrorMessage(error, 'LOCAL')
    this.#machine.send(localMessage)
    return { error: localMessage.payload }
  }

  /** Shorthand for sending a message to our peer. */
  #queueMessage<
    M extends ConnectionMessage, //
    T extends M['type'],
    P extends //
      M extends { payload: any } ? M['payload'] : undefined,
  >(type: T, payload?: P) {
    this.#messageQueue.send({ type, payload } as M)
  }

  #logMessage(direction: 'in' | 'out', message: NumberedMessage<ConnectionMessage>) {
    const arrow = direction === 'in' ? '<-' : '->'
    const peerUserName = this.#started ? this._context.peer?.userName ?? '?' : '?'
    this.logger.debug(`${arrow}${peerUserName} #${message.index} ${message.type}`)
  }
}

// MACHINE CONFIG FRAGMENTS
// These are snippets of XState config that are used repeatedly in the machine definition.

// error handler
const fail = (error: ConnectionErrorType) =>
  ({
    actions: [{ type: 'fail', params: { error } }, 'onDisconnected'],
    target: '#disconnected',
  }) as const

// timeout configuration
const TIMEOUT_DELAY = 30_000
const timeout = { after: { [TIMEOUT_DELAY]: fail(TIMEOUT) } } as const

// TYPES

export type ConnectionParams = {
  /** A function to send messages to our peer. This how you hook this up to your network stack. */
  sendMessage: (message: Uint8Array) => void

  /** The initial context. */
  context: Context
  createLogger?: (packageName: string) => SharedLogger
}
