import { describe, expect, it } from 'vitest'
import { symmetric, randomKey } from '../index.js'
import sodium from 'libsodium-wrappers-sumo'
import { stretch } from '../stretch.js'

async function* stream(chunks: Uint8Array[]) {
  yield* chunks
}
async function collect(source: AsyncIterable<Uint8Array>) {
  const result: Uint8Array[] = []
  for await (const chunk of source) result.push(chunk)
  return result
}

describe('authenticated attachment stream completion', () => {
  it('rejects a valid final tag carrying unexpected plaintext rather than silently discarding it', async () => {
    const key = randomKey(32)
    const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(stretch(key))
    const final = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array([1]),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    )
    await expect(
      collect(symmetric.decryptBytesStream(stream([final]), header, key))
    ).rejects.toThrow()
  })
  it.each([
    ['multi-chunk', [new Uint8Array([1, 2]), new Uint8Array([3, 4])]],
    ['empty', []],
  ] as const)('round-trips a %s file', async (_name, plaintext) => {
    const key = randomKey(32)
    const encrypted = symmetric.encryptBytesStream(stream([...plaintext]), key)
    const ciphertext = await collect(encrypted.encryptStream)
    expect(
      await collect(symmetric.decryptBytesStream(stream(ciphertext), encrypted.header, key))
    ).toEqual(plaintext)
  })

  it.each(['truncate', 'empty', 'reorder', 'append', 'corrupt', 'wrong-key'])(
    'rejects %s without reporting a completed file',
    async attack => {
      const key = randomKey(32)
      const encrypted = symmetric.encryptBytesStream(
        stream([new Uint8Array([1]), new Uint8Array([2])]),
        key
      )
      let ciphertext = await collect(encrypted.encryptStream)
      if (attack === 'truncate') ciphertext.pop()
      if (attack === 'empty') ciphertext = []
      if (attack === 'reorder') [ciphertext[0], ciphertext[1]] = [ciphertext[1], ciphertext[0]]
      if (attack === 'append') ciphertext.push(ciphertext[0])
      if (attack === 'corrupt') ciphertext[0][0] = (ciphertext[0][0] + 1) % 256
      await expect(
        collect(
          symmetric.decryptBytesStream(
            stream(ciphertext),
            encrypted.header,
            attack === 'wrong-key' ? randomKey(32) : key
          )
        )
      ).rejects.toThrow()
    }
  )
})
