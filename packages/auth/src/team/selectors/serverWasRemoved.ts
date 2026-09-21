import { type TeamState } from 'team/types.js'

export const serverWasRemoved = (state: TeamState, serverId: string) =>
  state.removedServers.some(s => s.serverId === serverId)
