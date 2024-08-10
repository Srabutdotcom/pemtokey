/// <reference lib="dom" />

/**
 * ! @preserve
 * To extract privateKey from Pem string into cryptoKey Object
 * @param {string} pem encoded base64 string
 * @param {256|384|512} hash either 256, 384 or 512
 * @returns Promise<CryptoKey> a promise that resolves to a CryptoKey
 */
export function pem2key(pem: string, hash?: 256 | 384 | 512): Promise<CryptoKey>;
