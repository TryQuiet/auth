import type {
  Base58,
  Graph,
  Hash,
  KeyMetadata,
  Keyring,
  Keyset,
  KeysetWithSecrets,
  Link,
  LinkBody,
  Payload,
  ROOT,
  Sequence,
  SignerInfo,
  UnixTimestamp,
} from '@localfirst/crdx'
import type { Client, LocalContext } from 'team/context.js'
import type { Device } from 'device/index.js'
import type {
  DeviceInvitationClaim,
  Invitation,
  InvitationState,
  MemberInvitationClaim,
  ProofOfInvitation,
} from 'invitation/types.js'
import type { Lockbox } from 'lockbox/index.js'
import type { PermissionsMap, Role } from 'role/index.js'
import type { Server } from 'server/index.js'
import type { ValidationResult } from 'util/index.js'
import { Logger, SharedLogger } from '@localfirst/shared'

// ********* MEMBER

/** A member is a user that belongs to a team. */
export type Member = {
  /** Unique ID populated on creation. */
  userId: string

  /** Username (or email). Must be unique but is not used for lookups. Only provided to connect
   * human identities with other systems. */
  userName: string

  /** The member's public keys */
  keys: Keyset

  /** Array of role names that the member belongs to */
  roles: string[]

  /** Devices that the member has registered */
  devices?: DeviceRecord[]
}

/**
 * A device as it appears in team state: the registered device plus when it was registered and, for
 * tombstones, when it was removed. A removed device id is never registered again, so a tombstone is
 * permanent — it's how we tell "this signer was removed" apart from "we've never heard of this
 * signer", which are different answers to a peer trying to connect.
 */
export type DeviceRecord = Device & {
  /** Timestamp of the link that registered this device */
  admittedAt: UnixTimestamp

  /** Timestamp of the link that removed this device (tombstones only) */
  removedAt?: UnixTimestamp
}

/** A server as it appears in team state; see `DeviceRecord` for the timestamps. */
export type ServerRecord = Server & {
  admittedAt: UnixTimestamp
  removedAt?: UnixTimestamp
}

/**
 * A member as it appears in a link that registers one. Its devices are plain devices: the
 * `admittedAt` stamp on the state record comes from the registering link, not from the payload, so
 * nobody gets to choose their own registration time.
 */
export type NewMember = Omit<Member, 'devices'> & { devices?: Device[] }

// ********* TEAM CONSTRUCTOR

/** Properties required when creating a new team */
export type NewTeamOptions = {
  /** The team's human-facing name */
  teamName: string

  /** The team keys need to be provided for encryption and decryption. It's up to the application to persist these somewhere.  */
  teamKeys: KeysetWithSecrets

  /** Team metadata (e.g. roles that can be self-assigned by a member on the chain) */
  metadata?: TeamMetadata
}

/** Properties required when rehydrating from an existing graph  */
export type ExistingTeamOptions = {
  /** The `TeamGraph` representing the team's state, to be rehydrated.
   *  Can be serialized or not. */
  source: Uint8Array | TeamGraph

  /** The team keys need to be provided for encryption and decryption. It's up to the application to persist these somewhere.  */
  teamKeyring: Keyring
}

type NewOrExisting = NewTeamOptions | ExistingTeamOptions

/** Options passed to the `Team` constructor */
export type TeamOptions = NewOrExisting & {
  /** A seed for generating keys. This is typically only used for testing, to ensure predictable data. */
  seed?: string

  /** Object containing the current user and device (and optionally information about the client & version). */
  context: LocalContext

  /** Logging instance shared with main application */
  sharedLogger?: SharedLogger
}

/** Type guard for NewTeamOptions vs ExistingTeamOptions  */
export const isNewTeam = (options: NewOrExisting): options is NewTeamOptions =>
  'teamName' in options

// ********* ACTIONS

type BasePayload = {
  // Every action might include new lockboxes
  lockboxes?: Lockbox[]
}

export type RootAction = {
  type: typeof ROOT
  payload: BasePayload & {
    name: string
    rootMember: Member
    rootDevice: Device
    metadata?: TeamMetadata
  }
}

export type AddMemberAction = {
  type: 'ADD_MEMBER'
  payload: BasePayload & {
    member: NewMember
    roles?: string[]
  }
}

export type RemoveMemberAction = {
  type: 'REMOVE_MEMBER'
  payload: BasePayload & {
    userId: string
  }
}

export type AddRoleAction = {
  type: 'ADD_ROLE'
  payload: BasePayload & Role
}

export type RemoveRoleAction = {
  type: 'REMOVE_ROLE'
  payload: BasePayload & {
    roleName: string
  }
}

export type AddMemberRoleAction = {
  type: 'ADD_MEMBER_ROLE'
  payload: BasePayload & {
    userId: string
    roleName: string
    permissions?: PermissionsMap
  }
}

export type RemoveMemberRoleAction = {
  type: 'REMOVE_MEMBER_ROLE'
  payload: BasePayload & {
    userId: string
    roleName: string
  }
}

export type RemoveDeviceAction = {
  type: 'REMOVE_DEVICE'
  payload: BasePayload & {
    deviceId: string
  }
}

export type InviteMemberAction = {
  type: 'INVITE_MEMBER'
  payload: BasePayload & {
    invitation: Invitation
  }
}

export type InviteDeviceAction = {
  type: 'INVITE_DEVICE'
  payload: BasePayload & {
    invitation: Invitation
  }
}

export type RevokeInvitationAction = {
  type: 'REVOKE_INVITATION'
  payload: BasePayload & {
    id: string // Invitation ID
  }
}

/**
 * Admits a new member and the device they'll use, in a single link.
 *
 * The payload carries the invitation proof and the claim it was signed over, so that every replica
 * can re-derive the admitted identity from signed material rather than trusting the admitting
 * peer's summary of it. The member and the device both come out of `claim`.
 */
export type AdmitMemberAction = {
  type: 'ADMIT_MEMBER'
  payload: BasePayload & {
    /** Invitation ID */
    id: Base58

    /** Proof that the invitee knows the invitation seed */
    proof: ProofOfInvitation

    /** The identity being registered; the reducer builds the member and their device from this */
    claim: MemberInvitationClaim

    /** The new device's signature over the claim — proof that whoever is being admitted actually
     * holds the device keys. The inviter knows the seed and can forge `proof`; it can't forge
     * this. */
    possessionProof: Base58
  }
}

/** Admits an additional device for an existing member. The device's owner comes from the
 * invitation record on the graph, never from the claim. */
export type AdmitDeviceAction = {
  type: 'ADMIT_DEVICE'
  payload: BasePayload & {
    id: Base58 // Invitation ID
    proof: ProofOfInvitation
    claim: DeviceInvitationClaim
    possessionProof: Base58
  }
}

export type ChangeMemberKeysAction = {
  type: 'CHANGE_MEMBER_KEYS'
  payload: BasePayload & {
    keys: Keyset
  }
}

export type RotateKeysAction = {
  type: 'ROTATE_KEYS'
  payload: BasePayload & {
    userId: string
  }
}

export type AddServerAction = {
  type: 'ADD_SERVER'
  payload: BasePayload & {
    server: Server
  }
}

export type RemoveServerAction = {
  type: 'REMOVE_SERVER'
  payload: BasePayload & {
    /** A server is identified by its `serverId` (the fingerprint of its identity key), never by its
     * host — a host is a mutable label. */
    serverId: string
  }
}

export type ChangeServerKeysAction = {
  type: 'CHANGE_SERVER_KEYS'
  payload: BasePayload & {
    keys: Keyset
  }
}

export type MessageAction = {
  type: 'MESSAGE'
  payload: BasePayload & {
    message: unknown
  }
}

export type SetTeamNameAction = {
  type: 'SET_TEAM_NAME'
  payload: BasePayload & {
    teamName: string
  }
}

export type AddLockboxesAction = {
  type: 'ADD_LOCKBOXES'
  payload: BasePayload & {
    lockboxes: Lockbox[]
  }
}

export type SetMetadataAction = {
  type: 'SET_METADATA'
  payload: BasePayload & {
    metadata: TeamMetadata
  }
}

export type TeamAction =
  | RootAction
  | AddMemberAction
  | AddRoleAction
  | AddMemberRoleAction
  | RemoveMemberAction
  | RemoveDeviceAction
  | RemoveRoleAction
  | RemoveMemberRoleAction
  | InviteMemberAction
  | InviteDeviceAction
  | RevokeInvitationAction
  | AdmitMemberAction
  | AdmitDeviceAction
  | ChangeMemberKeysAction
  | RotateKeysAction
  | AddServerAction
  | RemoveServerAction
  | ChangeServerKeysAction
  | MessageAction
  | SetTeamNameAction
  | AddLockboxesAction
  | SetMetadataAction

/**
 * Application context added to every link. It deliberately says nothing about who authored the
 * link: that's `body.signer`, which is bound to the link by a signature. Anything in here is an
 * unauthenticated hint and must never be used for authorization.
 */
export type TeamContext = {
  client?: Client
}

/** The kinds of signer that can author a team link. */
export const SignerKind = { DEVICE: 'device', SERVER: 'server' } as const
export type SignerKind = (typeof SignerKind)[keyof typeof SignerKind]

/** A signer resolved against team state: the record it names, and what kind of thing that is. */
export type ResolvedSigner =
  | { kind: typeof SignerKind.DEVICE; device: DeviceRecord }
  | { kind: typeof SignerKind.SERVER; server: ServerRecord }

export type TeamSignerInfo = SignerInfo & { kind: SignerKind }

export type TeamLinkBody = LinkBody<TeamAction, TeamContext>

export type TeamLink = Link<TeamAction, TeamContext> & {
  isInvalid?: boolean
}

export type TeamLinkMap = Record<Hash, TeamLink>
export type TeamGraph = Graph<TeamAction, TeamContext>
export type Branch = Sequence<TeamAction, TeamContext>
export type TwoBranches = [Branch, Branch]
/** Maps each signer id known to a graph to the member it acts for. */
export type SignerUserMap = Record<string, string>

export type MembershipRuleEnforcer = (
  links: TeamLink[],
  graph: TeamGraph,
  authors: SignerUserMap
) => TeamLink[]

// ********* TEAM STATE

export type TeamState = {
  head: Hash[]

  teamName: string
  members: Member[]
  roles: Role[]
  servers: ServerRecord[]
  lockboxes: Lockbox[]
  invitations: InvitationMap
  messages: unknown[]

  // We keep track of removed members and devices primarily so that we deliver the correct message
  // to them when we refuse to connect
  removedMembers: Member[]
  removedDevices: DeviceRecord[]
  removedServers: ServerRecord[]

  // If a member's admission is reversed, we need to flag them as compromised so an admin can
  // rotate any keys they had access to at the first opportunity
  pendingKeyRotations: string[]
  metadata: TeamMetadata
}

export type InvitationMap = Record<string, InvitationState>

// ********* VALIDATION

export type TeamStateValidator = (
  previousState: TeamState,
  link: TeamLink,
  extendableLogger: Logger
) => ValidationResult

export type TeamStateValidatorSet = Record<string, TeamStateValidator>

/**
 * The authenticated author of a link, derived from `body.signer` after its signature has been
 * verified against the registered record.
 *
 * Authorization rules take this rather than reading anything off the link body: a link body is
 * whatever its author chose to write, and the whole point of the signature is that this isn't.
 */
export type LinkAuthor = {
  /** The signer record the link's signature was verified against. */
  signer: ResolvedSigner

  /** The member the signer acts as: a device's owner, or a server's member projection. */
  member: Member
}

export type AuthorizedValidator = (
  previousState: TeamState,
  link: TeamLink,
  author: LinkAuthor,
  extendableLogger: Logger
) => ValidationResult

export type AuthorizedValidatorSet = Record<string, AuthorizedValidator>

// ********* CRYPTO

export type EncryptedEnvelope = {
  contents: Uint8Array
  recipient: KeyMetadata
}

export type SignedEnvelope = {
  contents: Payload
  signature: Base58
  author: KeyMetadata
}

export type Transform = (state: TeamState) => TeamState
export type InviteResult = {
  /** The unique identifier for this invitation. */
  id: Base58

  /** The secret invitation key. (Returned in case it was generated randomly.) */
  seed: string

  /** Immutable root hash identifying the team this invitation belongs to. */
  teamId: Base58
}
export type LookupIdentityResult =
  | 'VALID_DEVICE'
  | 'MEMBER_REMOVED'
  | 'DEVICE_UNKNOWN'
  | 'DEVICE_REMOVED'
  | 'VALID_SERVER'
  | 'SERVER_REMOVED'

export type EncryptStreamTeamPayload = { recipient: KeyMetadata, encryptStream: AsyncGenerator<Uint8Array>, header: Uint8Array }

export type TeamMetadata = { selfAssignableRoles: string[] }
