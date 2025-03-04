/**
 * Handles user-related chain operations
 */

//import { KeyMap } from '../../../../../../packages/auth/dist/team/selectors/keyMap.js'
import { BaseChainService } from '../baseService.js'
import { ProspectiveUser, MemberSearchOptions, DEFAULT_SEARCH_OPTIONS } from './types.js'
import { DeviceWithSecrets, LocalUserContext, Member, User, UserWithSecrets } from '@localfirst/auth'
import { SigChain } from '../../chain.js'
import { DeviceService } from './deviceService.js'
import { InviteService } from '../invites/inviteService.js'
import { KeyMap } from '../../../../../../packages/auth/dist/team/selectors/keyMap.js'

class UserService extends BaseChainService {
  public static init(sigChain: SigChain): UserService {
    return new UserService(sigChain)
  }

  /**
   * Generates a brand new QuietUser instance with an initial device from a given username
   * 
   * @param name The username
   * @param id Optionally specify the user's ID (otherwise autogenerate)
   * @returns New QuietUser instance with an initial device
   */
  public static create(name: string, id?: string): LocalUserContext {
    const user: UserWithSecrets = SigChain.lfa.createUser(name, id)
    const device: DeviceWithSecrets = DeviceService.generateDeviceForUser(user.userId)

    return {
      user,
      device
    }
  }

  public static createFromInviteSeed(name: string, seed: string): ProspectiveUser {
    const context = this.create(name)
    const inviteProof = InviteService.generateProof(seed)
    const publicKeys = UserService.redactUser(context.user).keys

    return {
      context,
      inviteProof,
      publicKeys
    }
  }

  public getKeys(): KeyMap {
    return this.sigChain.team.allKeys()
  }

  public getAllMembers(): Member[] {
    return this.sigChain.team.members()
  }

  public getMembersById(memberIds: string[], options: MemberSearchOptions = DEFAULT_SEARCH_OPTIONS): Member[] {
    if (memberIds.length === 0) {
      return []
    }

    return this.sigChain.team.members(memberIds, options)
  }

  public getMemberByName(memberName: string): Member | undefined {
    return this.getAllMembers().find((member) => member.userName === memberName)
  }

  public static redactUser(user: UserWithSecrets): User {
    return SigChain.lfa.redactUser(user)
  }
}

export {
  UserService
}
