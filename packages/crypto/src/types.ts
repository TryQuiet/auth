export type Utf8 = string & { _utf8: false }
export type Base58 = string & { _base58: false }
export type Hash = Base58 & { _hash: false }

export type Payload = any // msgpacker can serialize anything

export type ByteKeypair = {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

export type Base58Keypair = {
  publicKey: Base58
  secretKey: Base58
}

export type SignedMessage = {
  /** The plaintext message to be verified */
  payload: Payload
  /** The signature for the message, encoded as a base58 string */
  signature: Base58
  /** The signer's public key, encoded as a base58 string */
  publicKey: Base58
}

export type Cipher = {
  nonce: Uint8Array
  message: Uint8Array
}

export type Encoder = (b: Uint8Array) => string
export type Password = string | Uint8Array

export type EncryptStreamResult = { encryptStream: AsyncGenerator<Uint8Array>, header: Uint8Array }

export class StreamEncryptError extends Error {
  constructor (message: string, options?: ErrorOptions) {
    super(message, options)
  }
}

export class StreamDecryptError extends Error {
  constructor (message: string, options?: ErrorOptions) {
    super(message, options)
  }
}

export const INVALID_STREAM_DECRYPT_ERROR_MSG = `Error while decrypting a byte stream

A decrypted chunk of this byte stream had an undefined tag.  This could mean:

* The chunk size written to the original source is different from the chunk size of the read stream
* The data in the encrypted stream is not encrypted
* The data in the encrypted stream was encrypted with a different protocol/format
`
