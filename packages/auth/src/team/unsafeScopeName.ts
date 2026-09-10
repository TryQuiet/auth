const inheritedObjectNames = new Set([
  ...Object.getOwnPropertyNames(Object.prototype),
  ...Object.getOwnPropertyNames(Function.prototype),
  'prototype',
])

/** True when a graph-controlled scope name aliases a JavaScript meta-property or inherited name. */
export const isUnsafeScopeName = (value: string) => inheritedObjectNames.has(value)
