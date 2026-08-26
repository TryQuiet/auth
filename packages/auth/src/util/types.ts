export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<T>

// KEY TYPES

export const KeyType = {
  GRAPH: 'GRAPH',
  TEAM: 'TEAM',
  ROLE: 'ROLE',
  USER: 'USER',
  DEVICE: 'DEVICE',

  /** A server's rotatable keys — the ones lockboxes are addressed to. */
  SERVER: 'SERVER',

  /** A server's immutable signing identity, which authors its links. Kept in a separate scope from
   * `SERVER` so that a rotatable keyset can never be mistaken for an identity keyset. */
  SERVER_IDENTITY: 'SERVER_IDENTITY',

  EPHEMERAL: 'EPHEMERAL',
} as const
export type KeyType = (typeof KeyType)[keyof typeof KeyType]

// VALIDATION

export type InvalidResult = {
  isValid: false
  error: ValidationError
}

export type ValidResult = {
  isValid: true
}

export class ValidationError extends Error {
  constructor(message: string, details?: any) {
    super()
    this.message = message
    this.details = details
  }

  public name: 'Signature chain validation error'
  public details?: any
}

export type ValidationResult = ValidResult | InvalidResult
