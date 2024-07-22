/**
 * Handles user-related chain operations
 */

import { KeyMap } from '../../../../../../packages/auth/dist/team/selectors/keyMap.js'
import { BaseChainService } from '../baseService.js'
import { ProspectiveUser, MemberSearchOptions, DEFAULT_SEARCH_OPTIONS } from './types.js'
import { DeviceWithSecrets, LocalUserContext, Member, User, UserWithSecrets } from '@localfirst/auth'
import { SigChain } from '../../chain.js'

class UserService extends BaseChainService {
  protected static _instance: UserService | undefined

  public static init(): UserService {
    if (UserService._instance == null) {
      UserService._instance = new UserService() 
    }

    return UserService.instance
  }

  /**
   * Generates a brand new QuietUser instance with an initial device from a given username
   * 
   * @param name The username
   * @param id Optionally specify the user's ID (otherwise autogenerate)
   * @returns New QuietUser instance with an initial device
   */
  public create(name: string, id?: string): LocalUserContext {
    const user: UserWithSecrets = SigChain.lfa.createUser(name, id)
    const device: DeviceWithSecrets = SigChain.devices.generateDeviceForUser(user.userId)

    return {
      user,
      device
    }
  }

  public createFromInviteSeed(name: string, seed: string): ProspectiveUser {
    const context = this.create(name)
    const inviteProof = SigChain.invites.generateProof(seed)
    const publicKeys = UserService.redactUser(context.user).keys

    return {
      context,
      inviteProof,
      publicKeys
    }
  }

  public getKeys(): KeyMap {
    return this.activeSigChain.team.allKeys()
  }

  public getAllMembers(): Member[] {
    return this.activeSigChain.team.members()
  }

  public getMembersById(memberIds: string[], options: MemberSearchOptions = DEFAULT_SEARCH_OPTIONS): Member[] {
    if (memberIds.length === 0) {
      return []
    }

    return this.activeSigChain.team.members(memberIds, options)
  }

  public static redactUser(user: UserWithSecrets): User {
    return SigChain.lfa.redactUser(user)
  }

  public static get instance(): UserService {
    if (UserService._instance == null) {
      throw new Error(`UserService hasn't been initialized yet!  Run init() before accessing`)
    }

    return UserService._instance
  }
}

export {
  UserService
}