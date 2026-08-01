/**
 * Handles invite-related chain operations
 */

import { BaseChainService } from '../baseService.js'
import { ValidationResult } from '../../../../../../packages/crdx/dist/validator/types.js'
import {
  Base58,
  Device,
  InvitationClaim,
  InvitationState,
  InviteResult,
  Keyset,
  ProofOfInvitation,
  UnixTimestamp,
} from '@localfirst/auth'
import { SigChain } from '../../chain.js'
import { RoleName } from '../roles/roles.js'

export const DEFAULT_MAX_USES = 1
export const DEFAULT_INVITATION_VALID_FOR_MS = 604_800_000 // 1 week

class InviteService extends BaseChainService {
  public static init(sigChain: SigChain): InviteService {
    return new InviteService(sigChain)
  }

  public create(
    validForMs: number = DEFAULT_INVITATION_VALID_FOR_MS,
    maxUses: number = DEFAULT_MAX_USES
  ) {
    const expiration = (Date.now() + validForMs) as UnixTimestamp
    const invitation: InviteResult = this.sigChain.team.inviteMember({
      expiration,
      maxUses,
    })
    // this.activeSigChain.persist()
    return invitation
  }

  public revoke(id: string) {
    this.sigChain.team.revokeInvitation(id)
    // this.activeSigChain.persist()
  }

  public getById(id: Base58): InvitationState {
    return this.sigChain.team.getInvitation(id)
  }

  /**
   * Creates a version-2 proof binding the invitation seed to the exact identity claim and both
   * handshake nonces.
   */
  public static generateProof(
    seed: string,
    claim: InvitationClaim,
    acceptorNonce: Base58,
    inviteeNonce: Base58
  ): ProofOfInvitation {
    return SigChain.lfa.invitation.generateProof({
      seed,
      claim,
      acceptorNonce,
      inviteeNonce,
    })
  }

  /**
   * Validates the exact invitation claim and requires the proof's acceptor nonce to match the
   * current handshake.
   */
  public validateProof(
    proof: ProofOfInvitation,
    claim: InvitationClaim,
    expectedAcceptorNonce: Base58
  ): boolean {
    const validationResult = this.sigChain.team.validateInvitation(
      proof,
      claim.invitationKind,
      claim,
      expectedAcceptorNonce
    ) as ValidationResult
    if (!validationResult.isValid) {
      console.error(`Proof was invalid or was on an invalid invitation`, validationResult.error)
      return false
    }

    return true
  }

  /**
   * Admits a member only when its version-2 proof matches the supplied identity, device, and
   * expected acceptor nonce. The accepted proof and claim are recorded in the team action.
   */
  public acceptProof(
    proof: ProofOfInvitation,
    username: string,
    publicKeys: Keyset,
    device: Device,
    expectedAcceptorNonce: Base58
  ) {
    this.sigChain.team.admitMember(proof, publicKeys, username, device, expectedAcceptorNonce)
    // this.activeSigChain.persist()
  }

  /**
   * Admits a proof-bound member, then assigns the admitted user to the standard member role.
   * Returns the admitted username.
   */
  public admitMemberFromInvite(
    proof: ProofOfInvitation,
    username: string,
    userId: string,
    publicKeys: Keyset,
    device: Device,
    expectedAcceptorNonce: Base58
  ): string {
    this.sigChain.team.admitMember(proof, publicKeys, username, device, expectedAcceptorNonce)
    this.sigChain.roles.addMember(userId, RoleName.MEMBER)
    // this.activeSigChain.persist()
    return username
  }

  public getAllInvites(): InvitationState[] {
    const inviteMap = this.sigChain.team.invitations()
    const invites: InvitationState[] = []
    for (const invite of Object.entries(inviteMap)) {
      invites.push(invite[1])
    }
    return invites
  }
}

export { InviteService }
