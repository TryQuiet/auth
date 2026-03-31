import { type Transform } from 'team/types.js'
import * as _ from 'lodash-es'

export const addSubRoles =
  (parentRole: string, subRoles: string[]): Transform =>
  state => ({
    ...state,
    roles: state.roles.map(role => ({
      ...role,
      subRoles: role.roleName === parentRole ? _.uniq([...role.subRoles, ...subRoles]) : role.subRoles,
    }))
  })
