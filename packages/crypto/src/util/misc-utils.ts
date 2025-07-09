import sodium, { Uint8ArrayOutputFormat } from 'libsodium-wrappers-sumo'

export const randomBytes = (length: number, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array => {
  return sodium.randombytes_buf(length, outputFormat)
}

export const to_base64 = (bytes: Uint8Array, variant?: sodium.base64_variants): string => {
  return sodium.to_base64(bytes, variant)
}

export const from_base64 = (str: string, variant?: sodium.base64_variants): Uint8Array => {
  return sodium.from_base64(str, variant)
}

export const to_hex = (bytes: Uint8Array): string => {
  return sodium.to_hex(bytes)
}

export const from_hex = (str: string): Uint8Array => {
  return sodium.from_hex(str)
}

export const compare = (first: Uint8Array, second: Uint8Array): number => {
  return sodium.compare(first, second)
}

export type base64_variants = sodium.base64_variants
export const base64_variants = sodium.base64_variants
