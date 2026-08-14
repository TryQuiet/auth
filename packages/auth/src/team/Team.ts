import { EventEmitter } from '@herbcaudill/eventemitter42'
import type {
  Hash,
  KeyMetadata,
  KeyScope,
  Keyring,
  Keyset,
  KeysetWithSecrets,
  Payload,
  Signer,
  Store,
  UnixTimestamp,
  UserWithSecrets,
} from '@localfirst/crdx'
import {
  createKeyset,
  createStore,
  getChildMap,
  getLatestGeneration,
  isKeyset,
  redactKeys,
} from '@localfirst/crdx'
import { randomKey, signatures, symmetric, type Base58 } from '@localfirst/crypto'
import { assert, Logger } from '@localfirst/shared'
import * as identity from 'connection/identity.js'
import { type Challenge } from 'connection/types.js'
import * as devices from 'device/index.js'
import { type Device } from 'device/index.js'
import * as invitations from 'invitation/index.js'
import { type InvitationClaim, type ProofOfInvitation } from 'invitation/index.js'
import { normalize } from 'invitation/normalize.js'
import * as lockbox from 'lockbox/index.js'
import { AddRoleInput, ADMIN, type Role } from 'role/index.js'
import { castServer } from 'server/castServer.js'
import { type Host, type Server } from 'server/types.js'
import { type LocalContext } from 'team/context.js'
import { KeyType, scopesMatch } from 'util/index.js'
import { ADMIN_SCOPE, ALL, TEAM_SCOPE, initialState } from './constants.js'
import { decryptTeamGraph } from './decryptTeamGraph.js'
import { membershipResolver as resolver } from './membershipResolver.js'
import { redactUser } from './redactUser.js'
import { reducer } from './reducer.js'
import * as select from './selectors/index.js'
import { maybeDeserialize, serializeTeamGraph } from './serialize.js'
import { deviceSigner } from './signer.js'
import type {
  DeviceRecord,
  EncryptedEnvelope,
  EncryptStreamTeamPayload,
  InvitationMap,
  InviteResult,
  Member,
  NewMember,
  ServerRecord,
  SignedEnvelope,
  TeamAction,
  TeamGraph,
  TeamOptions,
  TeamState,
} from './types.js'
import { isNewTeam } from './types.js'
import { canUserAddMemberToRole } from './validate.js'
import { isAdminOnlyActionType } from './isAdminOnlyAction.js'

const { DEVICE, SERVER, SERVER_IDENTITY, USER } = KeyType
/**
 * The `Team` class wraps a `TeamGraph` and exposes methods for adding and removing
 * members, assigning roles, creating and using invitations, and encrypting messages for
 * individuals, for the team, or for members of specific roles.
 */
export class Team extends EventEmitter<TeamEvents> {
  public state: TeamState = initialState

  private readonly store: Store<TeamState, TeamAction>
  private readonly context: LocalContext
  private readonly seed: string
  private logger: Logger

  /** The identity this instance signs links with: our device, or — on a server — the server itself. */
  private readonly signer: Signer

  /** Our member identity. On a server this is the server's projection as a member. */
  private readonly user: UserWithSecrets

  /** The keys that open lockboxes addressed to us: our device keys, or a server's rotatable keys. */
  private lockboxKeys: KeysetWithSecrets

  /**
   * We can make a team instance either by creating a brand-new team, or restoring one from a stored graph.
   */
  constructor(options: TeamOptions) {
    super()

    // ignore coverage
    this.seed = options.seed ?? randomKey()
    this.context = options.context

    if ('user' in options.context) {
      const { user, device } = options.context
      this.user = user
      this.lockboxKeys = device.keys
      // Members author links as their device: device keys never rotate, so a signature stays
      // checkable against the device's registration forever.
      this.signer = deviceSigner(device)
    } else {
      const { server } = options.context
      this.user = castServer.toUser(server)
      this.lockboxKeys = server.keys
      // A server signs with its identity keys, which are separate from the rotatable keys its
      // lockboxes are addressed to.
      this.signer = castServer.toSigner(server)
    }

    const moduleName = `auth:team:${this.userName}`
    this.logger = new Logger({ moduleName, sharedLogger: options.sharedLogger, extendSharedLogger: true })
    this.logger.debug('loading team')

    // Initialize a CRDX store for the team
    if (isNewTeam(options)) {
      this.logger.debug('creating new team', options.teamName)
      // Create a new team with the current user as founding member

      assert('user' in this.context, `Servers can't create teams`)
      const { user, device } = this.context

      // Team & role secrets are never stored in plaintext, only encrypted into individual
      // lockboxes. Here we generate new keysets for the team and for the admin role, and store
      // these in new lockboxes for the founding member
      const lockboxTeamKeysForMember = lockbox.create(options.teamKeys, user.keys)
      const adminKeys = createKeyset(ADMIN_SCOPE, this.seed)
      const lockboxAdminKeysForMember = lockbox.create(adminKeys, user.keys)

      // We also store the founding user's keys in a lockbox for the user's device
      const lockboxUserKeysForDevice = lockbox.create(user.keys, device.keys)

      // We're creating a new graph; this information is to be recorded in the root link. The
      // metadata rides along in the root rather than in a follow-up link, so that a team is exactly
      // one link old when it's created and there's no window in which it has no metadata.
      const rootPayload = {
        name: options.teamName,
        rootMember: redactUser(user),
        rootDevice: devices.redactDevice(device),
        metadata: options.metadata ?? { selfAssignableRoles: [] },
        lockboxes: [lockboxTeamKeysForMember, lockboxAdminKeysForMember, lockboxUserKeysForDevice],
      }

      // Create CRDX store
      this.store = createStore({
        signer: this.signer,
        reducer,
        resolver,
        initialState,
        rootPayload,
        keys: options.teamKeys,
        logger: this.logger,
      })
    } else {
      this.logger.debug('loading existing team')
      // Rehydrate a team from an existing graph
      // Create CRDX store
      this.store = createStore({
        signer: this.signer,
        reducer,
        resolver,
        initialState,
        graph: maybeDeserialize(options.source, options.teamKeyring),
        keys: options.teamKeyring,
        logger: this.logger,
      })
    }

    this.state = this.store.getState()
    this.logger = this.logger.extend(this.id)
    this.logger.debug('team loaded')

    // Wire up event listeners
    this.on('updated', () => {
      // If we're admin, check for pending key rotations
      this.checkForPendingKeyRotations()
    })
  }

  /** ************** PUBLIC API */

  public get graph() {
    return this.store.getGraph() as TeamGraph
  }

  /** We use the hash of the graph's root as a unique ID for the team. */
  public get id() {
    return this.graph.root as Base58
  }

  /** Returns this team's user-facing name. */
  public get teamName() {
    return this.state.teamName
  }

  public setTeamName(teamName: string) {
    this.dispatch({ type: 'SET_TEAM_NAME', payload: { teamName } })
  }

  /** ************** CONTEXT */

  public get userName() {
    return this.user.userId
  }

  public get userId() {
    return this.user.userId
  }

  private get isServer() {
    return 'server' in this.context
  }

  /** ************** TEAM STATE
   *
   * All the logic for *reading* team state is in selectors (see `/team/selectors`).
   *
   * Most of the logic for *modifying* team state is in transforms (see `/team/transforms`), which
   * are executed by the reducer. To mutate team state, we dispatch changes to the graph, and then
   * run the graph through the reducer to recalculate team state.
   *
   * Any crypto operations involving the current user's secrets (for example, opening or creating
   * lockboxes, or signing links) are done here, not in the selectors or in the reducer. Only the
   * public-facing outputs (for example, the resulting lockboxesInScope, or the signed links) are
   * posted on the graph.
   */

  public save = () => serializeTeamGraph(this.graph)

  /**
   * Merges another graph (e.g. from a peer) with ours.
   * @returns This `Team` instance.
   */
  public merge = (theirGraph: TeamGraph) => {
    // A graph from a peer arrives with plaintext links attached; those are theirs to write, so we
    // reconstruct every body from the ciphertext its hash commits to before merging.
    const authenticatedGraph = decryptTeamGraph({
      encryptedGraph: { ...theirGraph, childMap: getChildMap(theirGraph) },
      teamKeys: this.teamKeyring(),
      deviceKeys: this.lockboxKeys,
      extendableLogger: this.logger,
    })
    this.store.merge(authenticatedGraph)
    this.state = this.store.getState()

    this.emit('updated', { head: this.graph.head })
    return this
  }

  /** Add a link to the graph, then recompute team state from the new graph */
  public dispatch(action: TeamAction, teamKeys: KeysetWithSecrets = this.teamKeys()) {
    this.store.dispatch(action, teamKeys)
    this.state = this.store.getState()
    this.emit('updated', { head: this.graph.head })
  }

  /** ************** MEMBERS */

  /** Returns true if the team has a member with the given userId */
  public has = (userId: string) => select.hasMember(this.state, userId)

  /** Returns a list of all members on the team */
  public members(): Member[] // Overload: all members
  /** Returns the member with the given user name */
  public members(userId: string, options?: LookupOptions): Member // Overload: one member
  public members(userIds: string[], options?: LookupOptions): Member[] // Overload: one member
  //
  public members(userIdOrIds: string | string[] = ALL, options = { includeRemoved: true, throwOnMissing: true }): Member | Member[] {
    if (typeof userIdOrIds === 'string') {
      return userIdOrIds === ALL //
      ? this.state.members // All members
      : select.member(this.state, userIdOrIds, options) // One member
    }

    return select.members(this.state, userIdOrIds, options) // Many members
  }

  /**
   * Adds a member to the team, along with the device they'll use. Since this method assumes that
   * you know the member's secret keys, it only makes sense for unit tests. In real-world scenarios,
   * you'll need to use the `team.invite` workflow to add members without relying on some kind of
   * public key infrastructure.
   *
   * A member and their first device are registered together, in one link. There's no way to
   * register a device for an existing member here — that goes through a device invitation, so that
   * the device proves it holds its own keys.
   */
  public addForTesting = (user: UserWithSecrets, roles: string[] = [], device?: Device) => {
    if (this.has(user.userId)) return

    const member = { ...redactUser(user), roles, devices: device ? [device] : undefined }

    // Make lockboxes for the new member, and for their device to get at the member's keys
    const lockboxes = this.createMemberLockboxes(member)
    if (device) lockboxes.push(lockbox.create(user.keys, device.keys))

    // Post the member to the graph
    this.dispatch({
      type: 'ADD_MEMBER',
      payload: { member, roles, lockboxes },
    })
  }

  /** Remove a member from the team */
  public remove = (userId: string) => {
    // Create new keys & lockboxes for any keys this person had access to
    const lockboxes = this.rotateKeys({ type: USER, name: userId })

    // Post the removal to the graph
    this.dispatch({
      type: 'REMOVE_MEMBER',
      payload: {
        userId,
        lockboxes,
      },
    })
  }

  /** Returns true if the member was once on the team but was removed */
  public memberWasRemoved = (userId: string) => select.memberWasRemoved(this.state, userId)

  /** ************** ROLES */

  /** Returns all roles in the team */
  public roles(): Role[]
  /** Returns the role with the given name */
  public roles(roleName: string): Role
  //
  public roles(roleName: string = ALL): Role | Role[] {
    return roleName === ALL //
      ? this.state.roles // All roles
      : select.role(this.state, roleName) // One role
  }

  /** Returns true if the member with the given userId has the given role */
  public memberHasRole = (userId: string, roleName: string) =>
    select.memberHasRole(this.state, userId, roleName)

  /** Returns true if the member with the given userId is a member of the 3 role */
  public memberIsAdmin = (userId: string) => select.memberIsAdmin(this.state, userId)

  /** Returns true if the team has a role with the given name */
  public hasRole = (roleName: string) => select.hasRole(this.state, roleName)

  /** Returns a list of members who have the given role */
  public membersInRole = (roleName: string): Member[] => select.membersInRole(this.state, roleName)

  /** Returns a list of members who are in the admin role */
  public admins = (): Member[] => select.admins(this.state)

  /** Add a role to the team */
  public addRole = (input: AddRoleInput | string) => {
    let role: Role
    if (typeof input === 'string') {
      role = { roleName: input, createdBy: this.userId }
    } else {
      role = {
        ...input,
        createdBy: this.userId,
      }
    }

    // We're creating this role so we need to generate new keys
    const roleKeys = createKeyset({ type: KeyType.ROLE, name: role.roleName }, this.seed)

    const lockboxes: lockbox.Lockbox[] = []
    if (this.memberIsAdmin(this.userId)) {
      // Make a lockbox for the admin role, so that all admins can access this role's keys
      lockboxes.push(lockbox.create(roleKeys, this.adminKeys()))
    }

    // Post the role to the graph
    this.dispatch({
      type: 'ADD_ROLE',
      payload: { ...(role as Role), lockboxes: lockboxes },
    })

    // if we choose to add ourselves to the role we need to create our own lockbox and then dispatch
    // the event to add the role to our member record
    this._dispatchAddMemberRole(this.userId, role.roleName, [lockbox.create(roleKeys, this.context.user.keys)])
  }

  /** Remove a role from the team */
  public removeRole = (roleName: string) => {
    this._isRoleRemovable(roleName, true)

    this.dispatch({
      type: 'REMOVE_ROLE',
      payload: { roleName },
    })
  }

  private _isRoleRemovable = (roleName: string, assertOnFalse: boolean): boolean => {
    const anyRoleButAdmin = roleName !== ADMIN
    if (assertOnFalse) {
      assert(anyRoleButAdmin, 'Cannot remove admin role')
    }

    return anyRoleButAdmin
  }

  /** Dispatch the add role action */
  private _dispatchAddMemberRole(userId: string, roleName: string, lockboxes: lockbox.Lockbox[]) {
    this.dispatch({
      type: 'ADD_MEMBER_ROLE',
      payload: { userId, roleName, lockboxes },
    })
  }

  /** Give a member a role */
  public addMemberRole = (userId: string, roleName: string, decryptionKeys?: KeysetWithSecrets) => {
    // Make a lockbox for the role
    const member = this.members(userId)
    const allGenKeys = this.roleKeysAllGenerations(roleName, decryptionKeys)
    const lockboxRoleKeysForMember = allGenKeys.map(roleKeys => lockbox.create(roleKeys, member.keys))

    // Post the member role to the graph
    this._dispatchAddMemberRole(userId, roleName, lockboxRoleKeysForMember)
  }

  /** Give yourself a role */
  public addMemberRoleToSelf = (roleName: string, decryptionKeys: KeysetWithSecrets) => {
    assert(this.state.metadata.selfAssignableRoles.includes(roleName), `Cannot self-assign role ${roleName}`)
    this.addMemberRole(this.userId, roleName, decryptionKeys)
  }

  /** Remove a role from a member */
  public removeMemberRole = (userId: string, roleName: string) => {
    if (roleName === ADMIN) {
      const adminCount = this.membersInRole(ADMIN).length
      assert(adminCount > 1, "Can't remove the last admin")
    }

    // Create new keys & lockboxes for any keys this person had access to via this role
    const lockboxes = this.rotateKeys({ type: KeyType.ROLE, name: roleName })

    // Post the removal to the graph
    this.dispatch({
      type: 'REMOVE_MEMBER_ROLE',
      payload: { userId, roleName, lockboxes },
    })
  }

  /** Check if member is priveleged enough to perform a specific action */
  private _memberHasPrivelegeToPerformAction(memberId: string, actionType: TeamAction['type']): boolean {
    if (!isAdminOnlyActionType(actionType)) {
      return true
    }
    return this.memberIsAdmin(memberId)
  }

  /** Check if member has permissions to add members to a role */
  public memberCanAddMembersToRole(roleName: string, memberId: string): boolean {
    if (!this._memberHasPrivelegeToPerformAction(memberId, 'ADD_MEMBER_ROLE')) {
      return false
    }
    if (!this.memberHasRole(memberId, roleName)) {
      return false
    }
    return canUserAddMemberToRole(roleName, memberId, this.state)
  }

  /** Check if member has permissions to reevoke membership from a role */
  public memberCanRemoveMembersFromRole(roleName: string, memberId: string): boolean {
    if (!this._memberHasPrivelegeToPerformAction(memberId, 'REMOVE_MEMBER_ROLE')) {
      return false
    }
    return this.memberHasRole(memberId, roleName)
  }

  /** Check if member has permissions to create roles */
  public memberCanCreateRole(memberId: string): boolean {
    return this._memberHasPrivelegeToPerformAction(memberId, 'ADD_ROLE')
  }

  /** Check if member has permissions to delete a specific role */
  public memberCanDeleteRole(roleName: string, memberId: string): boolean {
    if (!this._memberHasPrivelegeToPerformAction(memberId, 'REMOVE_ROLE')) {
      return false
    }
    if (!this.memberHasRole(memberId, roleName)) {
      return false
    }
    return this._isRoleRemovable(roleName, false) 
  }

  /** ************** DEVICES */

  /** Returns true if the team has a device with this id */
  public hasDevice = (deviceId: string, options?: LookupOptions): boolean =>
    select.hasDevice(this.state, deviceId, options)

  /** Finds a device by its id. Throws if we don't have exactly one. */
  public device(deviceId: string, options?: LookupOptions): DeviceRecord {
    return select.device(this.state, deviceId, options)
  }

  /** Remove a member's device */
  public removeDevice = (deviceId: string) => {
    if (!this.hasDevice(deviceId)) throw new Error(`Device ${deviceId} not found`)

    // Create new keys & lockboxes for any keys this device had access to
    const lockboxes = this.rotateKeys({ type: DEVICE, name: deviceId })

    // Post the removal to the graph
    this.dispatch({
      type: 'REMOVE_DEVICE',
      payload: {
        deviceId,
        lockboxes,
      },
    })
  }

  /** Returns true if the device was once on the team but was removed */
  public deviceWasRemoved = (deviceId: string) => {
    return select.deviceWasRemoved(this.state, deviceId)
  }

  /** Finds the member that owns this device. Throws if there isn't exactly one. */
  public memberByDeviceId = (deviceId: string, options?: LookupOptions) => {
    return select.memberByDeviceId(this.state, deviceId, options)
  }

  /**
   * Checks a peer's answer to an identity challenge against the keys we have registered for it.
   *
   * A peer authenticates as the signer it authors links with: a device with its device keys, or a
   * server with its immutable identity keys.
   */
  public verifyIdentityProof = (challenge: Challenge, proof: Base58) => {
    const { type, name: id } = challenge
    const keys =
      type === DEVICE
        ? this.device(id, { includeRemoved: true }).keys
        : type === SERVER_IDENTITY
          ? this.servers(id, { includeRemoved: true }).identityKeys
          : undefined
    assert(keys, `Can't verify an identity claim of type ${type}`)

    return identity.verify(challenge, proof, keys).isValid
  }

  /** ************** INVITATIONS */

  /**
   * To invite a new member:
   *
   * Alice generates an invitation using a secret seed. The seed an be randomly generated, or
   * selected by Alice. Alice sends the invitation to Bob using a trusted channel.
   *
   * Meanwhile, Alice adds Bob to the graph as a new member, with appropriate roles (if
   * any) and any corresponding lockboxes.
   *
   * Bob can't authenticate directly as that member, since it has random temporary keys created by
   * Alice. Instead, Bob generates a proof of invitation, and when they try to connect to Alice or
   * Charlie they present that proof instead of authenticating.
   *
   * Once Alice or Charlie verifies Bob's proof, they send him the team graph. Bob uses that to
   * instantiate the team, then he updates the team with his real public keys and adds his current
   * device information.
   */
  public inviteMember({
    seed = invitations.randomSeed(),
    expiration,
  }: {
    /** A secret to be passed to the invitee via a side channel. If not provided, one will be randomly generated. */
    seed?: string

    /** Time when the invitation expires. If not provided, the invitation does not expire. */
    expiration?: UnixTimestamp
  } = {}): InviteResult {
    // Normalize the seed (all lower case, strip spaces & punctuation)
    seed = normalize(seed)

    // Generate invitation
    const invitation = invitations.create({ seed, expiration })
    const { id } = invitation

    // Post invitation to graph
    this.dispatch({
      type: 'INVITE_MEMBER',
      payload: { invitation },
    })

    // Return the secret invitation seed (to pass on to invitee) and the invitation id (which could be used to revoke later)
    return { id, seed }
  }

  /**
   *  To invite an existing member's device:
   *
   *  On his laptop, Bob generates an invitation using a secret seed. He gets that seed to his phone
   *  using a QR code or by typing it in.
   *
   *  On his phone, Bob connects to his laptop (or to Alice or Charlie). Bob's phone presents its
   *  proof of invitation.
   *
   *  Once an existing device (Bob's laptop or Alice or Charlie) verifies Bob's phone's proof, they
   *  send it the team graph. Using the graph, the phone instantiates the team, then adds itself as
   *  a device.
   */
  public inviteDevice({
    seed = invitations.randomSeed(),
    expiration = (Date.now() + 30 * 60 * 1000) as UnixTimestamp,
  }: {
    /** A secret to be passed to the device via a side channel. If not provided, one will be randomly generated. */
    seed?: string

    /** Time when the invitation expires. Defaults to 30 minutes from now. */
    expiration?: UnixTimestamp
  } = {}): InviteResult {
    assert(!this.isServer, "Servers can't invite a device")

    seed = normalize(seed)

    // Generate invitation. Like every invitation it is multi-use (bounded by expiration): a
    // use-counter can't be enforced under concurrency, so a device invitation relies on its short
    // default expiration rather than a single-use guarantee.
    const invitation = invitations.create({ seed, expiration, userId: this.userId })

    // In order for the invited device to be able to access the user's keys, we put the user keys in
    // a lockbox that can be opened by an ephemeral keyset generated from the secret invitation
    // seed.
    const starterKeys = invitations.generateStarterKeys(seed)
    const lockboxUserKeysForDeviceStarterKeys = lockbox.create(this.user.keys, starterKeys)

    const { id } = invitation

    // Post invitation to graph
    this.dispatch({
      type: 'INVITE_DEVICE',
      payload: {
        invitation,
        lockboxes: [lockboxUserKeysForDeviceStarterKeys],
      },
    })

    // Return the secret invitation seed (to pass on to invitee) and the invitation id (which could be used to revoke later)
    return { id, seed }
  }

  /** Revoke an invitation. */
  public revokeInvitation = (id: string) => {
    // Mark the invitation as revoked
    this.dispatch({
      type: 'REVOKE_INVITATION',
      payload: { id },
    })
  }

  /** Returns true if the invitation has ever existed in this team (even if it's been used or revoked) */
  public hasInvitation(id: Base58): boolean {
    return select.hasInvitation(this.state, id)
  }

  /** Gets the invitation corresponding to the given id. If it does not exist, throws an error. */
  public getInvitation = (id: Base58) => select.getInvitation(this.state, id)

  /**
   * Check that the invitation is still usable, that the proof of invitation checks out against the
   * claimed identity, and that whoever is claiming it holds the device's keys.
   */
  public validateInvitation = (
    proof: ProofOfInvitation,
    claim: InvitationClaim,
    possessionProof: Base58
  ) => {
    const { id } = proof
    if (!this.hasInvitation(id)) return invitations.fail("This invitation code doesn't match.")

    const invitation = this.getInvitation(id)

    // Make sure the invitation hasn't already been used, hasn't expired, and hasn't been revoked
    const canBeUsedResult = invitations.invitationCanBeUsed(invitation, Date.now())
    if (!canBeUsedResult.isValid) return canBeUsedResult

    // Validate the proof of invitation against the claim it was signed over
    const proofValidation = invitations.validate(proof, invitation, claim)
    if (!proofValidation.isValid) return proofValidation

    // ...and that the device being registered actually holds its own keys. We know the seed, so we
    // could have produced the proof above ourselves; only the device can produce this one.
    return invitations.validatePossessionProof({ invitationId: id, claim, proof: possessionProof })
  }

  public invitations(): InvitationMap {
    return select.invitations(this.state)
  }

  /**
   * An existing team member (or a server) calls this to admit a new member and their first device,
   * based on the invitee's proof of invitation.
   *
   * We post the proof and the claim on the graph rather than a summary of them, so that every
   * other replica re-derives the admitted identity from the same signed material we did.
   */
  public admitMember = (
    proof: ProofOfInvitation,
    claim: invitations.MemberInvitationClaim,
    possessionProof: Base58
  ) => {
    const validation = this.validateInvitation(proof, claim, possessionProof)
    if (!validation.isValid) throw validation.error

    const { id } = proof

    // We know the team keys, so we can put them in a lockbox for the new member now (even if we're
    // not an admin). We lockbox *every* generation, not just the latest: links written before a key
    // rotation — the root, always — can only be opened with the generation they were written under,
    // and a member admitted after a rotation would otherwise have no way to reach those keys (the
    // admission already hands them the full keyring over the wire; this persists it on the graph so
    // `teamKeyring()` can rebuild it). This mirrors how role keys are lockboxed for a new role member.
    const lockboxTeamKeysForMember = this.keysAllGenerations(TEAM_SCOPE).map(keys =>
      lockbox.create(keys, claim.memberKeys)
    )

    // Post admission to the graph
    this.dispatch({
      type: 'ADMIT_MEMBER',
      payload: {
        id,
        proof,
        claim,
        possessionProof,
        lockboxes: lockboxTeamKeysForMember,
      },
    })
  }

  /** An existing team member calls this to admit a new device based on proof of invitation */
  public admitDevice = (
    proof: ProofOfInvitation,
    claim: invitations.DeviceInvitationClaim,
    possessionProof: Base58
  ) => {
    const validation = this.validateInvitation(proof, claim, possessionProof)
    if (!validation.isValid) throw validation.error

    // Post admission to the graph. The device's owner comes from the invitation record, which the
    // reducer reads for itself — nothing about the owner travels in this payload.
    this.dispatch({
      type: 'ADMIT_DEVICE',
      payload: {
        id: proof.id,
        proof,
        claim,
        possessionProof,
      },
    })
  }

  /**
   * Once a newly admitted member has received the graph and can instantiate the team, they call
   * this to store their user keys in a lockbox their device can open.
   *
   * Their device was registered by the admission itself, so this link is authored by a signer the
   * team already knows. (Before device-signed links, this is where the new device registered
   * itself — which is exactly the hole that let an unregistered device vouch for itself.)
   */
  public join = (teamKeyring: Keyring) => {
    assert('user' in this.context, "Can't join as member on server")
    const { user, device } = this.context
    this.logger.debug('joining pre-existing team')

    const teamKeys = getLatestGeneration(teamKeyring)
    const lockboxUserKeysForDevice = lockbox.create(user.keys, device.keys)

    this.dispatch(
      {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [lockboxUserKeysForDevice] },
      },
      teamKeys
    )
  }

  /** ************** SERVERS */

  /**
   * A server is an always-on, always-connected device that is available to the team but does not
   * belong to any one member. For example, `automerge-repo` calls this a "sync server".
   *
   * A server has a host name that uniquely identifies it (e.g. `example.com`, `localhost:8080`, or
   * `188.26.221.135`).
   *
   * The expected usage is for the application to add a server or servers immediately after the team
   * is created. However, the application can add or remove servers at any time.
   *
   * Just before adding a server, the application should send it the latest graph and the team keys
   * (so it can decrypt the team graph). No invitation or authentication is necessary in this phase,
   * as a TLS connection to a trusted address is sufficient to ensure the security of that
   * connection. In response, the server should send back its public keys. This library is not
   * involved in that process.
   *
   * The application should then add the server to the team using `addServer`, passing in the
   * server's public keys. At that point the server will be able to authenticate with other devices
   * using the same protocol as for members.
   *
   * The only actions that a server can dispatch to the graph are `ADMIT_MEMBER` and `ADMIT_DEVICE`.
   * The server needs to be able to admit invited members and devices in order to support
   * star-shaped networks where every device connects to a server, rather than directly to each
   * other.)
   */
  public addServer = (server: Server) => {
    const lockboxes = this.createMemberLockboxes(castServer.toMember(server))

    this.dispatch({
      type: 'ADD_SERVER',
      payload: { server, lockboxes },
    })
  }

  /** Removes a server from the team. */
  public removeServer = (serverId: string) => {
    this.dispatch({
      type: 'REMOVE_SERVER',
      payload: { serverId },
    })
  }

  /** Returns a list of all servers on the team. */
  public servers(): ServerRecord[] // Overload: all servers
  /** Returns the server with the given serverId */
  public servers(serverId: string, options?: { includeRemoved: boolean }): ServerRecord // Overload: one server
  //
  public servers(
    serverId: string = ALL, //
    options = { includeRemoved: true }
  ) {
    return serverId === ALL //
      ? this.state.servers // All servers
      : select.server(this.state, serverId, options) // One server
  }

  /**
   * Returns every server registered under the given host.
   *
   * For display and routing only. A host is a label a server can change, and nothing stops two
   * servers from claiming the same one, so it can't identify anything — hence a list rather than a
   * single result.
   */
  public serversByHost = (host: Host, options = { includeRemoved: false }) =>
    select.serversByHost(this.state, host, options)

  /** Returns true if the server was once on the team but was removed */
  public serverWasRemoved = (serverId: string) => select.serverWasRemoved(this.state, serverId)

  public hasServer = (serverId: string, options = { includeRemoved: false }) =>
    select.hasServer(this.state, serverId, options)

  /** ************** MESSAGES */

  public addMessage = (message: unknown) => {
    this.dispatch({
      type: 'MESSAGE',
      payload: { message },
    })
  }

  public messages = <T = unknown>() => select.messages(this.state) as T[]

  /** ************** CRYPTO */

  /**
   * Symmetrically encrypt a payload for the given scope using keys available to the current user.
   *
   * > *Note*: Since this convenience function uses symmetric encryption, we can only use it to
   * encrypt for scopes the current user has keys for (e.g. the whole team, or roles they belong
   * to). If we need to encrypt asymmetrically, we use the functions in the crypto module directly.
   */
  public encrypt = (payload: Payload, roleName?: string): EncryptedEnvelope => {
    const scope = roleName ? { type: KeyType.ROLE, name: roleName } : TEAM_SCOPE
    const { secretKey, generation } = this.keys(scope)
    return {
      contents: symmetric.encryptBytes(payload, secretKey),
      recipient: { ...scope, generation },
    }
  }

  /** Decrypt a payload using keys available to the current user. */
  public decrypt = (message: EncryptedEnvelope): Payload => {
    const { secretKey } = this.keys(message.recipient)
    return symmetric.decryptBytes(message.contents, secretKey)
  }
  
  /**
   * Symmetrically encrypt a byte stream for the given scope using keys available to the current user.
   *
   * > *Note*: Since this convenience function uses symmetric encryption, we can only use it to
   * encrypt for scopes the current user has keys for (e.g. the whole team, or roles they belong
   * to). If we need to encrypt asymmetrically, we use the functions in the crypto module directly.
   */
  public encryptStream = (stream: AsyncIterable<Uint8Array>, roleName?: string): EncryptStreamTeamPayload => {
    const scope = roleName ? { type: KeyType.ROLE, name: roleName } : TEAM_SCOPE
    const { secretKey, generation } = this.keys(scope)
    
    const { header, encryptStream } = symmetric.encryptBytesStream(stream, secretKey)
    return {
      header,
      encryptStream,
      recipient: { ...scope, generation }
    }
  }

  /** Decrypt a byte stream using keys available to the current user and a header generated during encryption. */
  public decryptStream = (encryptedStream: AsyncIterable<Uint8Array>, header: Uint8Array, recipient: KeyMetadata): AsyncGenerator<any> => {
    const { secretKey } = this.keys(recipient)
    return symmetric.decryptBytesStream(encryptedStream, header, secretKey)
  }

  /** Sign a message using the current user's keys. */
  public sign = (contents: Payload): SignedEnvelope => {
    const {
      keys: {
        type,
        name,
        generation,
        signature: { secretKey },
      },
    } = this.user

    return {
      contents,
      signature: signatures.sign(contents, secretKey),
      author: { type, name, generation },
    }
  }

  /** Verify a signed message against the author's public key */
  public verify = (message: SignedEnvelope): boolean =>
    signatures.verify({
      payload: message.contents,
      signature: message.signature,
      publicKey: this.members(message.author.name).keys.signature,
    })

  /** ************** KEYS
   *
   * These methods all return keysets *with secrets* that are available to the local user. To get
   * other members' public keys, look up the member - the `keys` property contains their public keys.
   */

  /**
   * Returns the secret keyset (if available to the current device) for the given type and name. To
   * get other members' public keys, look up the member - the `keys` property contains their public
   * keys.
   */
  public keys = (scope: KeyMetadata | KeyScope, decryptionKeys: KeysetWithSecrets = this.lockboxKeys) =>
    select.keys(this.state, decryptionKeys, scope)

  public keysAllGenerations = (scope: KeyMetadata | KeyScope, decryptionKeys: KeysetWithSecrets = this.lockboxKeys) =>
    select.keysAllGen(this.state, decryptionKeys, scope)

  public allKeys = (decryptionKeys: KeysetWithSecrets = this.lockboxKeys) =>
    select.allKeys(this.state, decryptionKeys)

  /** Returns the keys for the given role. */
  public roleKeys = (roleName: string, generation?: number, decryptionKeys?: KeysetWithSecrets) =>
    this.keys({ type: KeyType.ROLE, name: roleName, generation }, decryptionKeys)

  /** Returns the keys for the given role. */
  public roleKeysAllGenerations = (roleName: string, decryptionKeys?: KeysetWithSecrets) =>
    this.keysAllGenerations({ type: KeyType.ROLE, name: roleName }, decryptionKeys)

  /** Returns the current team keys or a specific generation of team keys */
  public teamKeys = (generation?: number) => this.keys({ ...TEAM_SCOPE, generation })

  public teamKeyring = () => select.teamKeyring(this.state, this.lockboxKeys)

  /** Returns the admin keyset. */
  public adminKeys = (generation?: number) => this.roleKeys(ADMIN, generation)

  /**
   * Replaces a member's or a server's secret keyset with the one provided. (An admin can do this
   * for someone else; anyone can do it for themselves.)
   *
   * Only these two kinds of keys rotate. Device keys and a server's identity keys are what their
   * ids are fingerprints of, and what their past links were signed with — rotating them would
   * break every signature they've ever made.
   */
  public changeKeys = (newKeys: KeysetWithSecrets) => {
    const { type, name } = newKeys
    assert(
      type === USER || type === SERVER,
      `Only ${USER} and ${SERVER} keys can be rotated (not ${type})`
    )

    const isForServer = type === SERVER
    const currentKeys = isForServer ? this.servers(name).keys : this.members(name).keys
    newKeys.generation = currentKeys.generation + 1

    // Treat the old keys as compromised, and generate new lockboxes for any keys they could see
    const lockboxes = this.rotateKeys(newKeys)

    // Post the new public keys to the graph
    this.dispatch({
      type: isForServer ? 'CHANGE_SERVER_KEYS' : 'CHANGE_MEMBER_KEYS',
      payload: { keys: redactKeys(newKeys), lockboxes },
    })

    // If those were our own keys, start using the new ones
    if (name === this.userId) {
      this.user.keys = newKeys
      // A server's rotatable keys are also the keys its lockboxes are addressed to
      if (isForServer) this.lockboxKeys = newKeys
    }
  }

  /**
   * Create a new lockbox containing a role's current generation keys encrypted to an arbitrary keyset
   * 
   * @param roleName Role whose keys we want to encapsulate in the lockbox (must be a role the user has!)
   * @param encryptionKeys Keys to encrypt the lockbox to
   * @returns Generated lockbox
   */
  public createLockbox = (roleName: string, encryptionKeys: KeysetWithSecrets): lockbox.Lockbox[] => {
    const roleKeys = this.roleKeysAllGenerations(roleName)
    const lockboxes = roleKeys.map((keys) => lockbox.create(keys, encryptionKeys))
    this.dispatch({ type: 'ADD_LOCKBOXES', payload: { lockboxes }})
    return lockboxes
  }

  private checkForPendingKeyRotations() {
    // Only admins can rotate keys
    if (!this.memberIsAdmin(this.userId)) {
      return
    }

    for (const userId of this.state.pendingKeyRotations) {
      // We don't know if the user was added to any other roles, so we're just preemptively rotating
      // all lockboxes *we* can see (since we're an admin, we have access to all keys)
      const lockboxes = this.rotateKeys({
        type: USER,
        name: this.userId,
      })
      this.dispatch({ type: 'ROTATE_KEYS', payload: { userId, lockboxes } })
    }
  }

  private readonly createMemberLockboxes = (member: NewMember) => {
    const roleKeys = member.roles.map((roleName: string) => this.roleKeys(roleName))
    const createLockboxRoleKeysForMember = (keys: KeysetWithSecrets) => {
      return lockbox.create(keys, member.keys)
    }
    return [...roleKeys, this.teamKeys()].map(createLockboxRoleKeysForMember)
  }

  /**
   * Given a compromised scope (e.g. a member or a role), find all scopes that are visible from that
   * scope, and generates new keys and lockboxes for each of those. Returns all of the new lockboxes
   * in a single array to be posted to the graph.
   *
   * You can pass it a scope, or a keyset (which includes the scope information). If you pass a
   * keyset, it will replace the existing keys with these.
   *
   * @param compromised If `compromised` is a keyset, that will become the new keyset for the
   * compromised scope. If it is just a scope, new keys will be randomly generated for that scope.
   */
  private readonly rotateKeys = (compromised: KeyScope | KeysetWithSecrets) => {
    const newKeyset = isKeyset(compromised)
      ? compromised // We're given a keyset - use it as the new keys
      : createKeyset(compromised) // We're just given a scope - generate new keys for it

    // identify all the keys that are indirectly compromised
    const visibleScopes = select.visibleScopes(this.state, compromised)
    const otherNewKeysets = visibleScopes.map(scope => createKeyset(scope))

    // Generate new keys for each one
    const newKeysets = [newKeyset, ...otherNewKeysets]

    // Create new lockboxes for each of these
    const newLockboxes = newKeysets.flatMap(newKeyset => {
      const oldLockboxes = select.lockboxesInScope(this.state, newKeyset)

      return oldLockboxes.map(oldLockbox => {
        // Check whether we have new keys for the recipient of this lockbox
        const updatedKeyset = newKeysets.find(k => scopesMatch(k, oldLockbox.recipient))
        return lockbox.rotate({
          oldLockbox,
          newContents: newKeyset,
          // If we did, address the new lockbox to those keys
          updatedRecipientKeys: updatedKeyset ? redactKeys(updatedKeyset) : undefined,
        })
      })
    })

    return newLockboxes
  }
}

type LookupOptions = {
  includeRemoved: boolean
}

type TeamEvents = {
  updated: (payload: { head: Hash[] }) => void
}
