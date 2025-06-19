import sodium from 'libsodium-wrappers-sumo'
import { describe, expect, test } from 'vitest'
import { stretch, symmetric } from '../index.js'
import { unpack } from 'msgpackr'
import { Cipher } from '../types.js'

const { encrypt, decrypt } = symmetric

const plaintext = 'The leopard pounces at noon'
const zalgoText = 'ẓ̴̇a̷̰̚l̶̥͑g̶̼͂o̴̅͜ ̸̻̏í̴͜s̵̜͠ ̴̦̃u̸̼̎p̵̘̔o̵̦͑ǹ̵̰ ̶̢͘u̵̇ͅș̷̏'
const poop = '💩'
const password = 'hello123'
const longPassword = 'eRPpBTwwa6gruOTq03AXGRFuR4WxBS6l6pGIiVlQPydVzEoWT2ST6Xqlyr1+XqYmmFEr4lFJ/u7l43RWd1Pxmaw2uG9pCCjw2JLnaRYcuOTq03AXGRFuR4WxBS6l6pGIiVlQPydVzEoWT2ST6Xqlyr1+XqYmmFEr4lFJ/u7l43RWd1Pxmaw2uG9pCCjw2JLnaRYcuy5XcwHRSEI4l6pGIiVlQPydVzEoWT2ST6Xqlyr1+XqYmmFEr4lFJ/u7l43RWd1Pxmaw2uG9pCCjw2JLnaRYcuy5XcwHRSEI4Cdcq+faT3GTvBtQGjWBmt7zPutPQIMB7Ii4fQyiB3mt67z2F68Y0Eph0/9JIwXeGfOVVQt347PCPCA6hgXe7+i4W6ylyIIuEQzJMQYGzu+l/2ktYOHxgY3pF0AL8yHuRPG30HFd6aSncAPyOBUyTI4qZ4S1IXJNLyBOq8pwNHdsxnxKw3QZarHniyoUEpvI+wMUpSRxZMHQOgaKBWH/wNFi3DgX3wfZdZTaPCD0G/1msL/e9ZtvXN9PApgULXJQmrWUO2chw5ptB8/xGd6h0Q3yDt8vcN/muWyoCSn91VlDIvSh1NOoEX08JEI1x8HJ7OE9TwrYJFFfgDAeV1D53IEcVkKe+5rtfjjwQBgfx+DA13DEee/ODaghvhX/venLSrFYWRk55gCc2BIyKATjYjLmLSHZ16Z98j09Ii93V7+E7XbzSuRqRQykzCRLRB0NoF7mQL46gRLF2gNXiqVqIUiY1u9rouxWZhSFDBeqWxWBjo3WJ7hZaaUTKSeInW6FTQuVqu4Tdn0/I3rwIhAAebVCftbakaWcjVsFsdyS8CLoiQBXg50VyriiFc2ckfyFs+AJBpndXkGOlg99EtXvRPzAR9NunGQxupCiRO3bnZG1xuKV3Y2iNc17O/WPDwqTIx/0CCUkZuDuJoiqhX+HJ6uyE6tS/7WBLCuVURirMkjBKNanWRe0KVopZgYVw2IEWbvO+PG7TO227llOSlI7mLwRb+QUSYtHKihp5xedTYAfq3l4Mdvt2D/6+lehhL/ijvieWs/RR9TMZE7eZcLwj8powELqMDYaL9H7pNZN0ha1AhOX+LTVWwmGS8K7f/s7XCgT+bl93SBRVfXbPA7LLkEy2PMHk3Xel0fn8zbGi+Z5I0QiNRFF0RTIXwBTZexV187Mkbv9J9ophj6vGs9TdeU5ByzWAVEgxwWhycBeamrKVoSypjowrftqAElL9OVdTAt6YMf/SuFW+dLm6acYcuzCWXs3kIEzDEJJc8TzLX2+CLk9yRmv1KGGicgDLvEE3mMbrtX18aaR6JP1j1zdwmfs5VgqA+Z93KR0m3OrXy4sYNVlI3ciTcU4jFO29FlzNTjre1Bl96apbX4ZJ6dY0c5GPFJastjgE9KY6/L5OD5NN2TaWWgAVh/Rv0wBLsu0vTWBMgLBoml0Tv4txtFDJKYKxflsNKLk053be0WQP10aOsEacuLxleP7eshDL/SmGk0vro3Np75bmLuybchS5Ns472y/5tRqZum3xekYi8DkAmVFCPzBkmq4TFUu9IxcjUapqIxFP6WqEI5vSOW6cgrENh983E5nQ8+wvAKoBFbzd6/aLmIyWqocGZvBl2/vs+XUvkOP3+aXHt/EJQrB0t6CdHyyMzUqGsCZoa/5JNFVH'; // prettier-ignore

describe('crypto', () => {
  describe('symmetric encrypt/decrypt', () => {
    test.each`
      label               | message      | password
      ${'plain text'}     | ${plaintext} | ${password}
      ${'empty string'}   | ${''}        | ${password}
      ${'emoji message'}  | ${poop}      | ${password}
      ${'zalgo text'}     | ${zalgoText} | ${password}
      ${'empty password'} | ${plaintext} | ${''}
      ${'emoji password'} | ${plaintext} | ${poop}
      ${'long password'}  | ${plaintext} | ${longPassword}
      ${'zalgo password'} | ${plaintext} | ${zalgoText}
    `('round trip: $label', ({ message, password }: { message: string; password: string }) => {
      const cipher = encrypt(message, password)
      expect(decrypt(cipher, password)).toEqual(message)

      const attemptToDecrypt = () => decrypt(cipher, 'nachopassword')
      expect(attemptToDecrypt).toThrow()
    })

    test('encryptBytes/decryptBytes', () => {
      const secret = {
        foo: 'bar',
        pizza: 42,
      }

      const encrypted = symmetric.encryptBytes(secret, password)
      const decrypted = symmetric.decryptBytes(encrypted, password)
      expect(decrypted).toEqual(secret)
    })

    test('encryptBytes/decryptBytes - invisible salamanders - wrong key', () => {
      const secret = {
        foo: 'bar',
        pizza: 42,
      }

      const encrypted = symmetric.encryptBytes(secret, password)
      const attemptToDecrypt = () => symmetric.decryptBytes(encrypted, longPassword)
      expect(attemptToDecrypt).toThrow()
    })

    test('encryptBytes/decryptBytes - invisible salamanders - wrong tag', () => {
      const secret = {
        foo: 'bar',
        pizza: 42,
      }

      const encrypted = symmetric.encryptBytes(secret, password)
      const cipher = unpack(encrypted) as Cipher
      const newTag = sodium.crypto_auth(new Uint8Array([...cipher.nonce, ...cipher.mac]), stretch(new Uint8Array([1, 2, 3, 4, 5])))
      const fakeEncrypted = symmetric.packToUint8Array({ ...cipher, tag: newTag })
      const attemptToDecrypt = () => symmetric.decryptBytes(fakeEncrypted, password)
      expect(attemptToDecrypt).toThrow()
    })

    test('byte array as password', () => {
      const bytePassword = new Uint8Array([1, 2, 3, 4, 5])
      const encrypted = symmetric.encryptBytes(plaintext, bytePassword)
      const decrypted = symmetric.decryptBytes(encrypted, bytePassword)
      expect(decrypted).toEqual(plaintext)
    })
  })
})
