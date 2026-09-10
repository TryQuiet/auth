import type { TeamAction } from './types.js'

/** Quiet has no removal or key-rotation protocol in this release. This is fixed local policy,
 * never a graph-supplied capability or a switch a peer can enable. Channel deletion uses
 * OrbitDB metadata, not REMOVE_ROLE; its admin permission predicate remains available. */
export const isDisabledAction = ({ type }: Pick<TeamAction, 'type'>): boolean =>
  [
    'REMOVE_MEMBER',
    'REMOVE_MEMBER_ROLE',
    'REMOVE_ROLE',
    'REMOVE_DEVICE',
    'REMOVE_SERVER',
    'CHANGE_MEMBER_KEYS',
    'CHANGE_SERVER_KEYS',
    'ROTATE_KEYS',
  ].includes(type)
