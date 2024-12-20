/**
 * Handles generating the chain and aggregating all chain operations
 */

import * as auth from '@localfirst/auth'
import { LoadedSigChain } from './types.js'
import { UserService } from './services/members/userService.js'
import { RoleService } from './services/roles/roleService.js'
import { ChannelService } from './services/roles/channelService.js'
import { DeviceService } from './services/members/deviceService.js'
import { InviteService } from './services/invites/inviteService.js'
import { DMService } from './services/dm/dmService.js'
import { CryptoService } from './services/crypto/cryptoService.js'
import { RoleName } from './services/roles/roles.js'

class SigChain {
  private _team: auth.Team
  private _users: UserService | null = null
  private _devices: DeviceService | null = null
  private _roles: RoleService | null = null
  private _channels: ChannelService | null = null
  private _dms: DMService | null = null
  private _invites: InviteService | null = null
  private _crypto: CryptoService | null = null

  private constructor(team: auth.Team) {
    this._team = team
  }

  /**
   * Create a brand new SigChain with a given name and also generate the initial user with a given name
   * 
   * @param teamName Name of the team we are creating
   * @param username Username of the initial user we are generating
   */
  public static create(teamName: string, username: string): LoadedSigChain {
    const context = UserService.create(username)
    const team: auth.Team = this.lfa.createTeam(teamName, context)
    const sigChain = this.init(team)
    
    sigChain.roles.createWithMembers(RoleName.MEMBER, [context.user.userId])
    // sigChain.persist()

    return {
      sigChain,
      context
    }
  }

  public static createFromTeam(team: auth.Team, context: auth.LocalUserContext): LoadedSigChain {
    const sigChain = this.init(team)
    return {
     context,
     sigChain
    }
 }

  // TODO: Is this the right signature for this method?
  public static join(context: auth.LocalUserContext, serializedTeam: Uint8Array, teamKeyRing: auth.Keyring): LoadedSigChain {
    const team: auth.Team = this.lfa.loadTeam(serializedTeam, context, teamKeyRing)
    team.join(teamKeyRing)

    const sigChain = this.init(team)
    // sigChain.persist()

    return {
      sigChain,
      context
    }
  }

  private static init(team: auth.Team): SigChain {
    const sigChain = new SigChain(team)
    sigChain.initServices()

    return sigChain
  }

  private initServices() {
    this._users = UserService.init(this)
    this._devices = DeviceService.init(this)
    this._roles = RoleService.init(this)
    this._channels = ChannelService.init(this)
    this._dms = DMService.init(this)
    this._invites = InviteService.init(this)
    this._crypto = CryptoService.init(this)
  }

  // TODO: persist to storage
  public persist(): Uint8Array {
    return this.team.save() // this doesn't actually do anything but create the new state to save
  }

  get team(): auth.Team {
    return this._team
  }

  get teamGraph(): auth.TeamGraph {
    return this._team.graph
  }

  get users(): UserService {
    return this._users!
  }

  get roles(): RoleService {
    return this._roles!
  }

  get channels(): ChannelService {
    return this._channels!
  }

  get devices(): DeviceService {
    return this._devices!
  }

  get invites(): InviteService {
    return this._invites!
  }

  get dms(): DMService {
    return this._dms!
  }

  get crypto(): CryptoService {
    return this._crypto!
  }

  static get lfa(): typeof auth {
    return auth
  }
}

export {
  SigChain
}