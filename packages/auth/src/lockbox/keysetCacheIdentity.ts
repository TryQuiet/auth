import { type KeysetWithSecrets } from '@localfirst/crdx'

/** Cheap content identity; arbitrary objects/accessors still take the full validation path. */
export const keysetCacheIdentity = (keys: KeysetWithSecrets): string | undefined => {
  const data = (value: unknown, fields: string[]): Record<string, unknown> | undefined => {
    if (typeof value !== 'object' || value === null) return
    const descriptors = Object.getOwnPropertyDescriptors(value)
    if (Object.keys(descriptors).length !== fields.length) return
    if (!fields.every(field => Object.hasOwn(descriptors, field) && 'value' in descriptors[field]))
      return
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]))
  }
  const root = data(keys, ['type', 'name', 'generation', 'secretKey', 'encryption', 'signature'])
  if (root === undefined) return
  const encryption = data(root.encryption, ['publicKey', 'secretKey'])
  const signature = data(root.signature, ['publicKey', 'secretKey'])
  if (encryption === undefined || signature === undefined) return
  const strings = [
    root.type,
    root.name,
    root.secretKey,
    encryption.publicKey,
    encryption.secretKey,
    signature.publicKey,
    signature.secretKey,
  ]
  if (
    !strings.every(value => typeof value === 'string') ||
    typeof root.generation !== 'number' ||
    !Number.isSafeInteger(root.generation) ||
    root.generation < 0
  )
    return
  return JSON.stringify([root.generation, ...strings])
}
