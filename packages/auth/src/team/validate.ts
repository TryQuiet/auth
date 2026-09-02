import { ROOT, verifyLinkSignature, type Keyset } from '@localfirst/crdx'
import { Logger, truncateHashes } from '@localfirst/shared'
import { deviceIdentityIsValid } from 'device/index.js'
import * as invitations from 'invitation/index.js'
import { invitationCanBeUsed } from 'invitation/index.js'
import { castServer, serverIdentityIsValid } from 'server/index.js'
import { KeyType, VALID, ValidationError, actionFingerprint, deriveUserId } from 'util/index.js'
import { isAdminOnlyAction } from './isAdminOnlyAction.js'
import { isUnsafeScopeName } from './unsafeScopeName.js'
import * as select from './selectors/index.js'
import {
  SignerKind,
  type AuthorizedValidatorSet,
  type LinkAuthor,
  type ResolvedSigner,
  type TeamLink,
  type TeamState,
  type TeamStateValidator,
} from './types.js'

/**
 * Decides whether a link may be applied to the state that precedes it.
 *
 * Everything here runs against the *derived* author — the identity whose signature we verified —
 * and never against anything the link body claims about itself. A link body is written by whoever
 * authored the link, so `payload.userId` and friends are targets of an action, never evidence of
 * who is taking it.
 *
 * The order matters: resolve the signer, confirm it's who it says it is, check its signature,
 * confirm it's still allowed to act, and only then ask whether this particular action is permitted.
 * A failure here is a hard rejection — an invalid link never reaches the reducer. Rejections that
 * are only about *concurrency* (a signer removed on a parallel branch) live in the membership
 * resolver instead, which marks links invalid rather than throwing.
 */
export const validate: TeamStateValidator = (
  previousState: TeamState,
  link: TeamLink,
  extendableLogger?: Logger
) => {
  const logger =
    extendableLogger !== undefined && extendableLogger !== null
      ? extendableLogger.extend('validate')
      : new Logger({ moduleName: 'auth:validate' })

  // The root link can't be checked against anything that came before it, because nothing did. It is
  // the team's trust anchor: it declares the founding member and device, and it must be signed by
  // that device.
  if (link.body.type === ROOT) return validateRoot(previousState, link, logger)

  const resolution = resolveAuthor(previousState, link, logger)
  if (!resolution.isValid) return resolution

  for (const key of Object.keys(validators)) {
    const validation = validators[key](previousState, link, resolution.author, logger)
    if (!validation.isValid) return validation
  }

  return VALID
}

/**
 * Whether `assigningUserId` is permitted to grant `roleName` — either the role is self-assignable
 * or the actor is an admin. Shared by the ADD_MEMBER_ROLE validator and Team's `memberCan*`
 * permission predicates so both answer the question the same way.
 */
export const canUserAddMemberToRole = (
  roleName: string,
  assigningUserId: string,
  previousState: TeamState
): boolean => {
  const metadata = select.getMetadata(previousState)
  if (metadata.selfAssignableRoles.includes(roleName)) {
    return true
  }

  if (select.memberIsAdmin(previousState, assigningUserId)) {
    return true
  }

  return false
}

/** Confirms the root link was signed by the very device it names as the founding device. */
const validateRoot = (previousState: TeamState, link: TeamLink, logger: Logger) => {
  if (link.body.type !== ROOT) return VALID
  const { rootDevice, rootMember } = link.body.payload
  const { signer } = link.body

  if (signer.kind !== SignerKind.DEVICE || signer.id !== rootDevice.deviceId) {
    return fail('The root link must be signed by the founding device', previousState, link, logger)
  }

  if (!deviceIdentityIsValid(rootDevice)) {
    return fail(
      "The founding device's id is not the fingerprint of its signature key",
      previousState,
      link,
      logger
    )
  }

  if (!keysetMatches(rootMember.keys, KeyType.USER, rootMember.userId, 0)) {
    return fail("The founding member's key metadata is invalid", previousState, link, logger)
  }

  if (rootDevice.userId !== rootMember.userId) {
    return fail(
      'The founding device must belong to the founding member (userIds must match)',
      previousState,
      link,
      logger
    )
  }

  // The founder's id must be the one derived from their founding device — same rule as for any
  // member. This is what makes a userId recomputable rather than chosen, so no global uniqueness
  // scan is needed to keep it distinct; domain separation also guarantees it can never equal the
  // deviceId it's derived from.
  if (rootMember.userId !== deriveUserId(rootDevice.deviceId)) {
    return fail(
      "The founding member's id must be derived from the founding device",
      previousState,
      link,
      logger
    )
  }

  if (
    !verifyLinkSignature({
      hash: link.hash,
      signature: link.signature,
      publicKey: rootDevice.keys.signature,
    })
  ) {
    return fail(
      "The root link's signature does not verify against the founding device's key",
      previousState,
      link,
      logger
    )
  }

  return VALID
}

type AuthorResolution = { isValid: true; author: LinkAuthor } | ReturnType<typeof fail>

/**
 * Resolves `body.signer` to a registered identity, verifies the link's signature against that
 * identity's key, confirms the signer is still active, and derives the member it acts as.
 */
const resolveAuthor = (
  previousState: TeamState,
  link: TeamLink,
  extendableLogger: Logger
): AuthorResolution => {
  const logger = extendableLogger.extend('resolveAuthor')
  const { signer } = link.body

  // Tombstoned and removed signers are included in the lookup, so that a link from a removed
  // device fails as "removed" rather than as "never heard of it" — and so that a removed id can't
  // be quietly reused by someone else.
  const record = select.signerRecord(previousState, signer, { includeRemoved: true })
  if (record === undefined) {
    return fail(
      `Link signer '${signer.kind}:${signer.id}' is not registered on this team`,
      previousState,
      link,
      logger
    )
  }

  const identityIsValid =
    record.kind === SignerKind.DEVICE
      ? deviceIdentityIsValid(record.device)
      : serverIdentityIsValid(record.server)
  if (!identityIsValid) {
    return fail(
      `Registered identity for '${signer.id}' does not match its own keys`,
      previousState,
      link,
      logger
    )
  }

  const publicKey = signingKeyOf(record)
  if (!verifyLinkSignature({ hash: link.hash, signature: link.signature, publicKey })) {
    return fail(
      `Link signature does not verify against the keys registered for '${signer.id}'`,
      previousState,
      link,
      logger
    )
  }

  if (record.kind === SignerKind.DEVICE) {
    const { device } = record
    if (device.removedAt !== undefined) {
      return fail(`Device '${signer.id}' was removed from the team`, previousState, link, logger)
    }

    if (!select.hasMember(previousState, device.userId)) {
      return fail(
        `Device '${signer.id}' belongs to a member who is not on the team`,
        previousState,
        link,
        logger
      )
    }

    const member = select.member(previousState, device.userId)
    return { isValid: true, author: { signer: record, member } }
  }

  const { server } = record
  if (server.removedAt !== undefined) {
    return fail(`Server '${signer.id}' was removed from the team`, previousState, link, logger)
  }

  // A server participates in the key hierarchy as a member, keyed on its serverId.
  return { isValid: true, author: { signer: record, member: castServer.toMember(server) } }
}

/** The public key a signer's links are signed with. */
const signingKeyOf = (record: ResolvedSigner) =>
  record.kind === SignerKind.DEVICE
    ? record.device.keys.signature
    : // A server signs with its *identity* keys, which never rotate — so its old links keep
      // verifying after a CHANGE_SERVER_KEYS.
      record.server.identityKeys.signature

const validators: AuthorizedValidatorSet = {
  /** Graph-controlled role names must never alias JavaScript inherited/meta-properties. */
  roleNamesAreSafe(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('roleNamesAreSafe')
    const roleName =
      link.body.type === 'ADD_ROLE' ||
      link.body.type === 'REMOVE_ROLE' ||
      link.body.type === 'ADD_MEMBER_ROLE' ||
      link.body.type === 'REMOVE_MEMBER_ROLE'
        ? link.body.payload.roleName
        : undefined

    if (roleName !== undefined && isUnsafeScopeName(roleName)) {
      return fail(`Role name '${roleName}' is reserved`, previousState, link, logger)
    }
    return VALID
  },
  /**
   * A device invitation may only name the authenticated member who authored it. The invitation
   * record is the sole source of the admitted device's owner, so without this check any member
   * could attach a device they control to another member's identity (e.g. an admin's) and author
   * links as them.
   */
  deviceInvitationBelongsToAuthor(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('deviceInvitationBelongsToAuthor')
    if (link.body.type !== 'INVITE_DEVICE') return VALID

    if (link.body.payload.invitation.userId !== author.member.userId) {
      return fail('A device invitation must belong to its author', previousState, link, logger)
    }

    return VALID
  },

  /** A device-key publication is meaningful only for the member who owns that registered device. */
  publishUserKeysBelongsToDeviceOwner(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('publishUserKeysBelongsToDeviceOwner')
    if (link.body.type !== 'PUBLISH_USER_KEYS_TO_DEVICE') return VALID

    const { deviceId } = link.body.payload
    if (author.signer.kind !== SignerKind.DEVICE || author.signer.device.deviceId !== deviceId) {
      return fail(
        'USER keys may be published only by the device that receives them',
        previousState,
        link,
        logger
      )
    }

    if (!select.hasDevice(previousState, deviceId)) {
      return fail(
        `Cannot publish keys to unknown device '${deviceId}'`,
        previousState,
        link,
        logger
      )
    }

    const device = select.device(previousState, deviceId)
    if (device.userId !== author.member.userId) {
      return fail(
        'A member may publish USER keys only to its own device',
        previousState,
        link,
        logger
      )
    }

    return VALID
  },

  /** Invitation ids identify immutable records. Revocation changes the existing record in place;
   * no later invite action may overwrite it, revive it, or change its expiry/owner/kind. */
  invitationIdsAreUnique(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('invitationIdsAreUnique')
    if (link.body.type !== 'INVITE_MEMBER' && link.body.type !== 'INVITE_DEVICE') return VALID

    const { id } = link.body.payload.invitation
    if (select.hasInvitation(previousState, id)) {
      return fail(`Invitation id '${id}' is already in use`, previousState, link, logger)
    }

    return VALID
  },

  /** A server exists to relay, not to govern: it may admit invited members and devices, nothing else. */
  serversCanOnlyAdmit(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('serversCanOnlyAdmit')
    if (author.signer.kind !== SignerKind.SERVER) return VALID

    const { type } = link.body
    if (type !== 'ADMIT_MEMBER' && type !== 'ADMIT_DEVICE') {
      return fail(`A server cannot author ${type}`, previousState, link, logger)
    }

    return VALID
  },

  /**
   * Every id a link registers must be new to the team, across members, devices (including
   * tombstones) and servers.
   *
   * Ids are how a link's signature is traced back to a key, so two identities sharing one would
   * make authorship ambiguous — and reusing a tombstoned id would undo a removal.
   */
  registeredIdsAreUnique(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('registeredIdsAreUnique')
    const ids = registeredIds(link)
    if (ids.length === 0) return VALID

    if (new Set(ids).size !== ids.length) {
      return fail('This action registers duplicate ids', previousState, link, logger)
    }

    for (const id of ids) {
      if (select.identityIdIsInUse(previousState, id)) {
        return fail(`The id '${id}' is already in use`, previousState, link, logger)
      }
    }

    return VALID
  },

  /** Registered keysets have to carry the metadata the identity they belong to requires. */
  identityKeyMetadataIsValid(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('identityKeyMetadataIsValid')
    const { type, payload } = link.body

    if (type === 'ADD_MEMBER') {
      const { member } = payload
      const devices = member.devices ?? []
      const memberIsValid =
        keysetMatches(member.keys, KeyType.USER, member.userId, 0) &&
        devices.every(device => device.userId === member.userId && deviceIdentityIsValid(device))
      if (!memberIsValid) {
        return fail('New member or device key metadata is invalid', previousState, link, logger)
      }
    }

    if (type === 'ADD_SERVER' && !serverIdentityIsValid(payload.server)) {
      return fail('New server key metadata is invalid', previousState, link, logger)
    }

    if (type === 'CHANGE_MEMBER_KEYS') {
      const { keys } = payload
      if (!select.hasMember(previousState, keys.name)) {
        return fail('Cannot change keys for an unknown member', previousState, link, logger)
      }

      const member = select.member(previousState, keys.name)
      if (!keysetMatches(keys, KeyType.USER, member.userId, member.keys.generation + 1)) {
        return fail('Changed member key metadata is invalid', previousState, link, logger)
      }
    }

    if (type === 'CHANGE_SERVER_KEYS') {
      const { keys } = payload
      // Only the rotatable keyset can change. Identity keys are what a server's id commits to, so
      // rotating them would let a server take over another's registration.
      if (keys.type !== KeyType.SERVER) {
        return fail(
          `Only a server's ${KeyType.SERVER} keys can be rotated`,
          previousState,
          link,
          logger
        )
      }

      if (!select.hasServer(previousState, keys.name)) {
        return fail('Cannot change keys for an unknown server', previousState, link, logger)
      }

      const server = select.server(previousState, keys.name)
      if (!keysetMatches(keys, KeyType.SERVER, server.serverId, server.keys.generation + 1)) {
        return fail('Changed server key metadata is invalid', previousState, link, logger)
      }
    }

    return VALID
  },

  /** The user who made these changes was a member with appropriate rights at the time */
  mustBeAdmin(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('mustBeAdmin')
    if (
      isAdminOnlyAction(link.body) &&
      !select.memberIsAdmin(previousState, author.member.userId)
    ) {
      return fail(`Member '${author.member.userId}' is not an admin`, previousState, link, logger)
    }

    return VALID
  },

  /** Unless I'm an admin, I can't remove anyone's devices but my own */
  canOnlyRemoveYourOwnDevices(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('canOnlyRemoveYourOwnDevices')
    if (link.body.type !== 'REMOVE_DEVICE') return VALID

    if (select.memberIsAdmin(previousState, author.member.userId)) return VALID

    const target = link.body.payload.deviceId
    if (!select.hasDevice(previousState, target)) {
      return fail(`Device '${target}' is not on the team`, previousState, link, logger)
    }

    const device = select.device(previousState, target)
    if (author.member.userId !== device.userId) {
      return fail("Can't remove another user's device.", previousState, link, logger)
    }

    return VALID
  },

  /** A member's USER keys can only be replaced by that member. */
  canOnlyChangeYourOwnKeys(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('canOnlyChangeYourOwnKeys')
    const { type, payload } = link.body
    if (type !== 'CHANGE_MEMBER_KEYS') return VALID

    const target = payload.keys.name
    if (author.member.userId !== target) {
      return fail(`Can't change another user's keys.`, previousState, link, logger)
    }

    return VALID
  },

  /** Check for ADMIT with invitations that are revoked OR expired. */
  cantAdmitWithInvalidInvitation(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('cantAdmitWithInvalidInvitation')
    const { type, payload } = link.body
    if (type !== 'ADMIT_MEMBER' && type !== 'ADMIT_DEVICE') return VALID

    const { id } = payload
    if (!select.hasInvitation(previousState, id)) {
      return fail(`No invitation with id '${id}' was found`, previousState, link, logger)
    }

    return invitationCanBeUsed(select.getInvitation(previousState, id), link.body.timestamp)
  },

  /** A member invitation admits a member and a device invitation admits a device — never crossed. */
  admissionMatchesInvitationKind(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('admissionMatchesInvitationKind')
    const { type, payload } = link.body
    if (type !== 'ADMIT_MEMBER' && type !== 'ADMIT_DEVICE') return VALID

    const { id, claim } = payload
    const invitation = select.getInvitation(previousState, id)
    const expectedKind = type === 'ADMIT_MEMBER' ? 'member' : 'device'

    // `kind` was recorded by the reducer from the INVITE_MEMBER / INVITE_DEVICE action, so it can't
    // be talked into being something else by an admission.
    if (invitation.kind !== expectedKind) {
      return fail(
        `A ${invitation.kind} invitation cannot be used by ${type}`,
        previousState,
        link,
        logger
      )
    }

    if (claim.invitationKind !== expectedKind) {
      return fail(
        `The signed claim is for a ${claim.invitationKind} invitation, not a ${expectedKind} one`,
        previousState,
        link,
        logger
      )
    }

    if (type === 'ADMIT_DEVICE') {
      // A device invitation names the user the new device will belong to; the claim doesn't get a
      // say. Without an owner there's nothing to attach the device to.
      const { userId } = invitation
      if (userId === undefined) {
        return fail('Device invitation has no owner', previousState, link, logger)
      }

      if (!select.hasMember(previousState, userId)) {
        return fail(
          `The owner of this device invitation ('${userId}') is not on the team`,
          previousState,
          link,
          logger
        )
      }
    }

    return VALID
  },

  /**
   * Every replica re-checks an admission for itself, from the signed material in the payload.
   *
   * Two independent things have to hold: the invitee knew the invitation seed (`proof`), and
   * whoever is being registered actually holds the device's secret keys (`possessionProof`). Only
   * the second is beyond the inviter's reach — the inviter knows the seed, so it could mint a proof
   * of invitation for keys of its own choosing.
   */
  admissionProvesInvitationAndPossession(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('admissionProvesInvitationAndPossession')
    const { type, payload } = link.body
    if (type !== 'ADMIT_MEMBER' && type !== 'ADMIT_DEVICE') return VALID

    const { id, proof, claim, possessionProof } = payload
    if (!isRecord(proof) || !isRecord(claim) || typeof possessionProof !== 'string') {
      return fail('Admission is missing its proofs or its claim', previousState, link, logger)
    }

    const invitation = select.getInvitation(previousState, id)

    const proofValidation = invitations.validate(proof, invitation, claim)
    if (!proofValidation.isValid) {
      return fail(
        `Admission does not contain a valid invitation proof: ${proofValidation.error.message}`,
        previousState,
        link,
        logger
      )
    }

    const possessionValidation = invitations.validatePossessionProof({
      invitationId: id,
      claim,
      proof: possessionProof,
    })
    if (!possessionValidation.isValid) {
      return fail(
        `Admission does not prove possession of the device being registered: ${possessionValidation.error.message}`,
        previousState,
        link,
        logger
      )
    }

    return VALID
  },

  /**
   * An admitted member's userId isn't a label they chose — it's the hash of the device that founded
   * their identity (the device carried in this same admission). Re-deriving it here makes the id
   * self-certifying: every replica computes the same userId from the same device, so two distinct
   * members can never collide on one, and no global uniqueness scan is needed to keep them apart.
   *
   * Runs after the proof/possession check, so the claim's shape is already validated; the guard is
   * belt-and-suspenders against a malformed payload reaching this far.
   */
  admittedMemberIdIsDerivedFromDevice(previousState, link, _author, extendableLogger) {
    const logger = extendableLogger.extend('admittedMemberIdIsDerivedFromDevice')
    if (link.body.type !== 'ADMIT_MEMBER') return VALID

    const { claim } = link.body.payload
    const deviceId = claim?.device?.deviceId
    const userId = claim?.memberKeys?.name
    if (typeof deviceId !== 'string' || typeof userId !== 'string') {
      return fail(
        'Admission claim is missing the fields its member id derives from',
        previousState,
        link,
        logger
      )
    }

    if (userId !== deriveUserId(deviceId)) {
      return fail(
        "The admitted member's id must be derived from the device it registers",
        previousState,
        link,
        logger
      )
    }

    return VALID
  },

  /**
   * A role assignment is authorized against the *derived* author, never the userId the link body
   * claims to be acting as. #26's rule stands — a non-admin may only grant self-assignable roles —
   * but it now runs against `author.member.userId`, so a forged `payload.userId` can't launder an
   * assignment the signer isn't allowed to make.
   */
  nonAdminsCanOnlyModifyCertainRoles(previousState, link, author, extendableLogger) {
    const logger = extendableLogger.extend('nonAdminsCanOnlyModifyCertainRoles')
    if (link.body.type !== 'ADD_MEMBER_ROLE') return VALID

    const assigningUserId = author.member.userId
    const { roleName } = link.body.payload
    if (canUserAddMemberToRole(roleName, assigningUserId, previousState)) return VALID

    return fail(
      `User ${assigningUserId} attempted to assign role ${roleName} illegally`,
      previousState,
      link,
      logger
    )
  },
}

/** The identity ids a link registers, if any. */
const registeredIds = (link: TeamLink): string[] => {
  const { type, payload } = link.body
  switch (type) {
    case ROOT: {
      return [payload.rootMember.userId, payload.rootDevice.deviceId]
    }

    case 'ADD_MEMBER': {
      return [payload.member.userId, ...(payload.member.devices ?? []).map(d => d.deviceId)]
    }

    case 'ADMIT_MEMBER': {
      return [payload.claim.memberKeys.name, payload.claim.device.deviceId]
    }

    case 'ADMIT_DEVICE': {
      return [payload.claim.device.deviceId]
    }

    case 'ADD_SERVER': {
      return [payload.server.serverId]
    }

    default: {
      return []
    }
  }
}

const keysetMatches = (keys: Keyset, type: string, name: string, generation: number) =>
  keys.type === type &&
  keys.name === name &&
  keys.generation === generation &&
  typeof keys.encryption === 'string' &&
  typeof keys.signature === 'string'

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const fail = (
  message: string,
  previousState: TeamState,
  link: TeamLink,
  extendableLogger: Logger
) => {
  const logger = extendableLogger.extend('fail')
  message = truncateHashes(`${actionFingerprint(link)} ${message}`)
  logger.error(message, link.hash)
  return {
    isValid: false as const,
    error: new ValidationError(message, { prevState: previousState, link }),
  }
}
