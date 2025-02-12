import sodium, { StateAddress } from 'libsodium-wrappers-sumo'
import { pack, unpack } from 'msgpackr'
import { stretch } from './stretch.js'
import type { Base58, Cipher, Password, Payload } from './types.js'
import { base58, keyToBytes } from './util/index.js'

/**
 * Symmetrically encrypts a byte array.
 */
const encryptBytes = (
  /** The plaintext or object to encrypt */
  payload: Payload,
  /** The password used to encrypt */
  password: Password
): Uint8Array => {
  const messageBytes = pack(payload)
  const key = stretch(password)
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const encrypted = sodium.crypto_secretbox_easy(messageBytes, nonce, key)
  const cipher: Cipher = { nonce, message: encrypted }
  const cipherBytes = pack(cipher)
  return cipherBytes
}

/**
 * Symmetrically decrypts a message encrypted by `symmetric.encryptBytes`. Returns the original byte array.
 */
const decryptBytes = (
  /** The encrypted data in msgpack format */
  cipher: Uint8Array,
  /** The password used to encrypt */
  password: Password
): Payload => {
  const key = stretch(password)
  const { nonce, message } = unpack(cipher) as Cipher
  const decrypted = sodium.crypto_secretbox_open_easy(message, nonce, key)
  return unpack(decrypted)
}

/**
 * Symmetrically encrypts a byte stream.
 */
const encryptBytesStream = (
  /** The stream to encrypt */
  stream: AsyncIterable<Uint8Array>,
  /** The password used to encrypt */
  password: Password
): { encryptStream: AsyncGenerator<Uint8Array>, header: Uint8Array } => {
  const key = stretch(password)

  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

  const createEncryptStream = async function*(stream: AsyncIterable<Uint8Array>, state: StateAddress): AsyncGenerator<Uint8Array> {
    for await (const chunk of stream) {
      const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
        state,
        chunk,
        null,
        sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
      );
      yield encryptedChunk
      
    }

    // Finalize the stream
    const encryptedFinalChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array(),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    );
    yield encryptedFinalChunk
  }

  return {
    encryptStream: createEncryptStream(stream, state),
    header
  }
}

const decryptBytesStream = (
  /** The stream of encrypted bytes to decrypt */
  encryptedStream: AsyncIterable<Uint8Array>,
  /** Header bytes written to the encrypted stream */
  header: Uint8Array,
  /** The password used to encrypt */
  password: Password
): AsyncGenerator<any> => {
  const key = stretch(password)

  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  console.log(state, typeof state)

  const createDecryptStream = async function*(encryptedStream: AsyncIterable<Uint8Array>, state: StateAddress): AsyncGenerator<any> {
    for await (const chunk of encryptedStream) {
      const decryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_pull(
        state,
        chunk
      );
      // all valid encrypted chunks on the stream should end with this tag
      if (decryptedChunk.tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
        yield decryptedChunk.message
      } else if (decryptedChunk.tag != sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        console.error(`Unknown tag seen while decrypting stream`, decryptedChunk.tag)
      }
    }
  }

  return createDecryptStream(encryptedStream, state)
}

/**
 * Symmetrically encrypts a string or object. Returns the encrypted data, encoded in msgpack format
 * as a base58 string.
 */
const encrypt = (
  /** The plaintext or object to encrypt */
  payload: Payload,
  /** The password used to encrypt */
  password: Password
): Base58 => {
  const cipherBytes = encryptBytes(payload, password)
  const cipher = base58.encode(cipherBytes)
  return cipher
}

/**
 * Symmetrically decrypts a message encrypted by `symmetric.encrypt`.
 */
const decrypt = (
  /** The encrypted data in msgpack format, base58-encoded */
  cipher: Base58,
  /** The password used to encrypt */
  password: Password
): Payload => {
  const cipherBytes = keyToBytes(cipher)
  return decryptBytes(cipherBytes, password)
}

export const symmetric = { encryptBytes, decryptBytes, encrypt, decrypt, encryptBytesStream, decryptBytesStream }
