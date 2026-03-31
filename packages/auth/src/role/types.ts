export type PermissionsMap = Record<string, boolean>

export type Role = {
  roleName: string
  createdBy: string
  subRoles: string[]
  permissions?: PermissionsMap
}

export type AddRoleInput = Omit<Role, 'createdBy'>
