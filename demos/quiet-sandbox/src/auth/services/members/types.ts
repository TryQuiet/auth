import { Keyset, LocalUserContext } from "@localfirst/auth"

export type MemberSearchOptions = { 
  includeRemoved: boolean
  throwOnMissing: boolean 
}

export type ProspectiveUser = {
  context: LocalUserContext
  invitationSeed: string
  publicKeys: Keyset
}

export const DEFAULT_SEARCH_OPTIONS: MemberSearchOptions = { includeRemoved: false, throwOnMissing: true }
