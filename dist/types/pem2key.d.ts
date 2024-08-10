/**
 * ! @preserve
 * To extract privateKey from Pem string into cryptoKey Object
 * @param {base64} pem encoded base64 string
 * @param {256|384|512} hash either 256, 384 or 512
 * @returns Promise<CryptoKey> a promise that resolve a CryptoKey
 */
export function pem2key(pem: base64, hash?: 256 | 384 | 512): Promise<CryptoKey>;
