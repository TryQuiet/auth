import { Base58, Keyset, LocalUserContext, ProofOfInvitation } from "@localfirst/auth"

export type MemberSearchOptions = { 
  includeRemoved: boolean
  throwOnMissing: boolean 
}

export type ProspectiveUser = {
  context: LocalUserContext
  inviteProof: ProofOfInvitation
  publicKeys: Keyset
  acceptorNonce: Base58
}

export const DEFAULT_SEARCH_OPTIONS: MemberSearchOptions = { includeRemoved: false, throwOnMissing: true }
