import { type Logger } from '@localfirst/shared'
import { authorizedLockboxes } from 'team/lockboxAuthorization.js'
import {
  isLockboxCarrierAction,
  SignerKind,
  type TeamLink,
  type TeamState,
  type Transform,
} from 'team/types.js'

/**
 * Collects an action's explicit key deliveries. A `lockboxes` field on any other action is not a
 * delivery channel and is ignored, even when it arrived through an untyped/deserialized payload.
 */
export const collectLockboxes =
  (previousState: TeamState, link: TeamLink, logger: Logger): Transform =>
  projectedState => {
    const action = link.body
    const rawPayload = action.payload as unknown
    const hasLockboxes = isRecord(rawPayload) && Object.hasOwn(rawPayload, 'lockboxes')
    const carrierLink = isLockboxCarrierAction(action)
      ? link
      : legacyJoinPublicationLink(previousState, link, rawPayload)

    if (carrierLink === undefined) {
      if (hasLockboxes) {
        logger.warn(
          `Dropping lockboxes from ${action.type} link ${link.hash}: action cannot carry key deliveries`
        )
      }
      return projectedState
    }

    const payload = carrierLink.body.payload as unknown
    if (!hasLockboxes || !isRecord(payload) || !Object.hasOwn(payload, 'lockboxes')) {
      return projectedState
    }

    const newLockboxes = payload.lockboxes
    if (newLockboxes === undefined) return projectedState

    const authorized = authorizedLockboxes(
      previousState,
      projectedState,
      carrierLink,
      newLockboxes,
      logger
    )
    if (authorized.length === 0) return projectedState
    return { ...projectedState, lockboxes: projectedState.lockboxes.concat(authorized) }
  }

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * `ADD_LOCKBOXES` is no longer a public action, but old `Team.join()` links used it to publish a
 * member's USER key to the very device that signed the link. Translate only that historical shape
 * to the new semantic action. Other ambient deliveries stay inert, so compatibility cannot revive
 * the old generic key-distribution capability.
 */
const legacyJoinPublicationLink = (
  previousState: TeamState,
  link: TeamLink,
  payload: unknown
): TeamLink | undefined => {
  if (
    !isLegacyAddLockboxes(link.body) ||
    !isRecord(payload) ||
    !Object.hasOwn(payload, 'lockboxes')
  ) {
    return undefined
  }

  const { signer } = link.body
  if (signer.kind !== SignerKind.DEVICE) return undefined

  const deviceIsRegistered = previousState.members.some(member =>
    member.devices?.some(device => device.deviceId === signer.id)
  )
  if (!deviceIsRegistered) return undefined

  return {
    ...link,
    body: {
      ...link.body,
      type: 'PUBLISH_USER_KEYS_TO_DEVICE',
      payload: { deviceId: signer.id, lockboxes: payload.lockboxes },
    },
  } as TeamLink
}

const isLegacyAddLockboxes = (action: unknown) =>
  isRecord(action) && action.type === 'ADD_LOCKBOXES'
