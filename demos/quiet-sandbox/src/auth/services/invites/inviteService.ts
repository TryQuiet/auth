/**
 * Handles invite-related chain operations
 */

import { BaseChainService } from "../baseService.js"
import {
  Base58,
  DeviceWithSecrets,
  InvitationClaim,
  InvitationState,
  InviteResult,
  MemberInvitationClaim,
  ProofOfInvitation,
  UnixTimestamp,
  UserWithSecrets,
} from "@localfirst/auth"
import { SigChain } from "../../chain.js"
import { RoleName } from "../roles/roles.js"

export const DEFAULT_INVITATION_VALID_FOR_MS = 604_800_000 // 1 week

type InvitationProofParameters = {
  seed: string
  claim: InvitationClaim
  identityNonce: Base58
  inviteeNonce: Base58
}

type MemberAdmission = {
  proofOfInvitation: ProofOfInvitation
  claim: MemberInvitationClaim
  possessionProof: Base58
}

class InviteService extends BaseChainService {
  public static init(sigChain: SigChain): InviteService {
    return new InviteService(sigChain)
  }

  public create(validForMs: number = DEFAULT_INVITATION_VALID_FOR_MS) {
    const expiration = (Date.now() + validForMs) as UnixTimestamp
    const invitation: InviteResult = this.sigChain.team.inviteMember({
      expiration
    })
    // this.activeSigChain.persist()
    return invitation
  }

  public revoke(id: Base58) {
    this.sigChain.team.revokeInvitation(id)
    // this.activeSigChain.persist()
  }

  public getById(id: Base58): InvitationState {
    return this.sigChain.team.getInvitation(id)
  }

  public static generateProof(parameters: InvitationProofParameters): ProofOfInvitation {
    return SigChain.lfa.invitation.generateProof(parameters)
  }

  /**
   * Builds all signed material needed for a direct member admission. `identityNonce` must come
   * from the peer accepting the invitation; it cannot be chosen before the handshake starts.
   */
  public static createMemberAdmission({
    seed,
    user,
    device,
    identityNonce,
    inviteeNonce,
  }: {
    seed: string
    user: UserWithSecrets
    device: DeviceWithSecrets
    identityNonce: Base58
    inviteeNonce: Base58
  }): MemberAdmission {
    const claim: MemberInvitationClaim = {
      invitationKind: "member",
      userName: user.userName,
      memberKeys: SigChain.lfa.redactKeys(user.keys),
      device: SigChain.lfa.redactDevice(device),
    }
    const proofOfInvitation = this.generateProof({
      seed,
      claim,
      identityNonce,
      inviteeNonce,
    })
    const possessionProof = SigChain.lfa.invitation.createPossessionProof({
      invitationId: proofOfInvitation.id,
      claim,
      device,
    })

    return { proofOfInvitation, claim, possessionProof }
  }

  public validateProof(
    proof: ProofOfInvitation,
    claim: InvitationClaim,
    possessionProof: Base58
  ): boolean {
    const validationResult = this.sigChain.team.validateInvitation(proof, claim, possessionProof)
    if (!validationResult.isValid) {
      console.error(`Proof was invalid or was on an invalid invitation`, validationResult.error)
      return false
    }

    return true
  }

  public acceptProof(
    proof: ProofOfInvitation,
    claim: MemberInvitationClaim,
    possessionProof: Base58
  ) {
    this.sigChain.team.admitMember(proof, claim, possessionProof)
    // this.activeSigChain.persist()
  }

  public admitMemberFromInvite(
    proof: ProofOfInvitation,
    claim: MemberInvitationClaim,
    possessionProof: Base58
  ): string {
    this.acceptProof(proof, claim, possessionProof)
    this.sigChain.roles.addMember(claim.memberKeys.name, RoleName.MEMBER)
    // this.activeSigChain.persist()
    return claim.userName
  }

  public getAllInvites(): InvitationState[] {
    return Object.values(this.sigChain.team.invitations())
  }
}

export {
  InviteService
}
