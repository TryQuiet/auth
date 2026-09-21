import { fingerprint, type Base58 } from '@localfirst/crypto'
import { assert } from '@localfirst/shared'
import { arrayToMap } from './arrayToMap.js'
import { type Signer } from 'graph/types.js'
import { createKeyset, type KeysetWithSecrets } from 'keyset/index.js'

/** A `Signer` with the name we know it by in tests. */
export type TestSigner = Signer & { name: string }

/**
 * Creates a test signer whose id is the fingerprint of its own signing key, the way applications
 * built on crdx are expected to derive signer ids. crdx itself never checks this — `id` is an
 * opaque string as far as the library is concerned.
 */
export const createTestSigner = (name: string, kind = 'test'): TestSigner => {
  const keys = createKeyset({ type: 'SIGNER', name })
  return {
    name,
    info: { kind, id: fingerprint(keys.signature.publicKey) },
    keys,
  }
}

/**
Usage:

```ts
const {alice, bob} = setup('alice', 'bob')
```
*/
export const setup = (...names: string[]) => {
  assert(names.length > 0)

  const testSigners: Record<string, TestSigner> = names
    .map(name => createTestSigner(name))
    .reduce(arrayToMap('name'), {})

  return testSigners
}

export const TEST_GRAPH_KEYS: KeysetWithSecrets = {
  type: 'GRAPH',
  name: 'GRAPH',
  generation: 0,
  signature: {
    publicKey: 'GQrmBanGPSFBvZ4AHAoduk1jp7tXxa5fuzmWQTfbCbRT' as Base58,
    secretKey:
      'P7AgGTmMNedfpDixXF1rJgmVpyqAwCnGJRqyQzbm5wQbUnfoySAWMBzjxcm8USprqRNcW2ZoEEbzwPRX7EFuZkD' as Base58,
  },
  encryption: {
    publicKey: '7QviM4tWnhSwrrmrZnqEm3vFWrp3nvFwdcQShaFZ7nXj' as Base58,
    secretKey: 'HiFFKM6Eg1zkDHYkFcDLpEq7BM3k3FywHpj4zxQzVvHj' as Base58,
  },
  secretKey: 'GUg4dKHG1KWnysf4tsMtbBXvbuknj2q34qvjxYZzc5eP' as Base58,
}
