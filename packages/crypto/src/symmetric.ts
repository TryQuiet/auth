import sodium, { StateAddress } from 'libsodium-wrappers-sumo'
import { pack, unpack } from 'msgpackr'
import { stretch } from './stretch.js'
import { DecryptError, INVALID_STREAM_DECRYPT_ERROR_MSG, INVALID_TAG_DECRYPT_ERROR_MSG, StreamDecryptError, StreamEncryptError, type Base58, type Cipher, type Password, type Payload } from './types.js'
import { base58, keyToBytes } from './util/index.js'

/**
 * Symmetrically encrypts a byte array and calculate a hash of the nonce and authentication
 * tag to prevent invisible salamanders attacks
 * 
 * References:
 *  - https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#robustness
 *  - https://github.com/TryQuiet/quiet/issues/2711
 */
const encryptBytes = (
  /** The plaintext or object to encrypt */
  payload: Payload,
  /** The password used to encrypt */
  password: Password
): Uint8Array => {
  const messageBytes = packToUint8Array(payload)
  const key = stretch(password)
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const secretBox = sodium.crypto_secretbox_detached(messageBytes, nonce, key)
  const tag = sodium.crypto_auth(new Uint8Array([...nonce, ...secretBox.mac]), key)
  const cipher: Cipher = { nonce, tag, message: secretBox.cipher, mac: secretBox.mac }
  const cipherBytes = packToUint8Array(cipher)
  return cipherBytes
}

/**
 * Symmetrically decrypts a message encrypted by `symmetric.encryptBytes` after validating
 * the tag against the nonce and mac to prevent invisible salamanders attacks
 * 
 * Returns the original byte array
 * 
 * References:
 *  - https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#robustness
 *  - https://github.com/TryQuiet/quiet/issues/2711
 */
const decryptBytes = (
  /** The encrypted data in msgpack format */
  cipher: Uint8Array,
  /** The password used to encrypt */
  password: Password
): Payload => {
  const key = stretch(password)
  const { nonce, message, tag, mac } = unpack(cipher) as Cipher
  const tagValid = sodium.crypto_auth_verify(tag, new Uint8Array([...nonce, ...mac]), key)
  if (!tagValid) {
      throw new DecryptError(INVALID_TAG_DECRYPT_ERROR_MSG)
  }
  const decrypted = sodium.crypto_secretbox_open_detached(message, mac, nonce, key)
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
  // Prepare stream for encryption
  const key = stretch(password)

  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

  // Encrypt stream
  const createEncryptStream = async function*(stream: AsyncIterable<Uint8Array>, state: StateAddress): AsyncGenerator<Uint8Array> {
    // Encrypt each chunk of the stream with message tag
    for await (const chunk of stream) {
      try {
        const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          chunk,
          null,
          sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        );
        yield encryptedChunk
      } catch (e) {
        throw new StreamEncryptError(`Error while encrypting byte stream message`, {
          cause: e
        })
      }
    }

    // Finalize the stream with the final tag
    try {
      const encryptedFinalChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
        state,
        new Uint8Array(),
        null,
        sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      );
      yield encryptedFinalChunk
    } catch (e) {
      throw new StreamEncryptError(`Error while encrypting final message of byte stream`, {
        cause: e
      })
    }
  }

  return {
    encryptStream: createEncryptStream(stream, state),
    header // this header is required for decrypting later
  }
}

/**
 * Symmetrically decrypts a byte stream.
 */
const decryptBytesStream = (
  /** The stream of encrypted bytes to decrypt */
  encryptedStream: AsyncIterable<Uint8Array>,
  /** Header bytes written to the encrypted stream */
  header: Uint8Array,
  /** The password used to encrypt */
  password: Password
): AsyncGenerator<any> => {
  // Prepare stream for decryption
  const key = stretch(password)

  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);

  // Decrypt stream
  const createDecryptStream = async function*(encryptedStream: AsyncIterable<Uint8Array>, state: StateAddress): AsyncGenerator<any> {
    // Decrypt each chunk of the byte stream
    for await (const chunk of encryptedStream) {
      try {
        const decryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state,
          chunk
        );

        switch (decryptedChunk.tag) {
          // all valid encrypted chunks on the stream should end with this tag
          case sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
            yield decryptedChunk.message
            break
          // the final tag is only here to mark the end of the stream but contains no valid information
          case sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            break
          // if we are missing a tag that means something is wrong with the incoming stream
          case undefined:
            throw new StreamDecryptError(INVALID_STREAM_DECRYPT_ERROR_MSG)
          // any other tag means we've hit an issue
          default:
            throw new StreamDecryptError(`Invalid tag ${decryptedChunk.tag} seen while decrypting byte stream`)
        }
      } catch (e) {
        if (e instanceof StreamDecryptError) {
          throw e
        }

        throw new StreamDecryptError(`Error while decrypting byte stream`, {
          cause: e
        })
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

const packToUint8Array = (
  payload: Payload
): Uint8Array => {
  return new Uint8Array(pack(payload))
}

export const symmetric = { encryptBytes, decryptBytes, encrypt, decrypt, encryptBytesStream, decryptBytesStream, packToUint8Array }
