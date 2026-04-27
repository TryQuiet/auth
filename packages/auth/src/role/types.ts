export enum Permission {
  MODIFIABLE_MEMBERSHIP = 'modifiable-membership',
}

export interface ModifiableMembershipPermissionConfig {
  memberIds: string[]
}

export type PermissionsMap = { 
  [Permission.MODIFIABLE_MEMBERSHIP]?: true | ModifiableMembershipPermissionConfig 
}

export type Role = {
  roleName: string
  createdBy: string
  permissions?: PermissionsMap
}

export type AddRoleInput = Omit<Role, 'createdBy'>
