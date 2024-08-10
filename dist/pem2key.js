/// <reference types="./types/pem2key.d.ts" /> 
// ../../aid/ensure/ensurePem.js
var pemTypes = Object.freeze({
  "RSA PRIVATE KEY": "RSA PRIVATE KEY",
  "CERTIFICATE": "CERTIFICATE",
  "RSA PUBLIC KEY": "RSA PUBLIC KEY",
  "DSA PRIVATE KEY": "DSA PRIVATE KEY",
  "PUBLIC KEY": "PUBLIC KEY",
  "PRIVATE KEY": "PRIVATE KEY",
  "PKCS7": "PKCS7",
  "NEW CERTIFICATE REQUEST": "NEW CERTIFICATE REQUEST",
  "CERTIFICATE REQUEST": "CERTIFICATE REQUEST",
  "X509 CRL": "X509 CRL",
  "EC PRIVATE KEY": "EC PRIVATE KEY",
  "(RSA |EC )?PRIVATE KEY": "(RSA |EC )?PRIVATE KEY",
  "(RSA )?PUBLIC KEY": "(RSA )?PUBLIC KEY"
});
function ensurePem(pem, type) {
  pem = ensureString(pem);
  type = ensurePemType(type);
  const test = pemRegex(type).test(pem);
  if (test == false)
    throw TypeError(`Expected PEM format ${type}`);
  return pem;
}
function pemRegex(pemType) {
  return new RegExp(`^(-----BEGIN ${pemType}-----\r?
?(?:[A-Za-z0-9+/=]+\r?
?)*-----END ${pemType}-----)\r?
?$`);
}
function ensurePemType(type) {
  const isTrue = Object.prototype.hasOwnProperty.call(pemTypes, type);
  if (!isTrue)
    throw TypeError(`Unexpected PEM type : ${type}`);
  return type;
}
function ensureString(string) {
  if (typeof string !== "string")
    throw TypeError(`Expected string but got ${typeof string}`);
  return string;
}

// pem2key.js
import { Base64 } from "npm:@lapo/asn1js@2.0.4/base64.js";
import { ASN1 } from "npm:@lapo/asn1js@2.0.4";
import { Defs } from "npm:@lapo/asn1js@2.0.4/defs.js";
import * as jose from "npm:jose@5.6.3";
//! @preserve deno-lint-ignore-no-var-file
var keyFormats = Object.freeze({
  "PKCS#8": "PKCS#8",
  "PKCS#1": "PKCS#1"
});
var keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
/**
 * ! @preserve
 * To extract privateKey from Pem string into cryptoKey Object
 * @param {string} pem encoded base64 string
 * @param {256|384|512} hash either 256, 384 or 512
 * @returns Promise<CryptoKey> a promise that resolve a CryptoKey
 */
async function pem2key(pem, hash = 256)/* :Promise<CryptoKey> */ {
  pem = ensurePem(pem, pemTypes["(RSA |EC )?PRIVATE KEY"]);
  if ([256, 384, 512].includes(hash) == false)
    throw TypeError(`Invalid hash ${hash}`);
  const byte = Base64.unarmor(pem);
  const asn1 = ASN1.decode(byte);
  const key = parseKey(asn1);
  /**
   * ! @preserve
   * @type {CryptoKey} type - standard of CryptoKey */
  let cryptoKey = keyPair.privateKey;
  if (key.type == keyFormats["PKCS#8"]) {
    if (key.name.includes("ec")) {
      if (key.alg.includes("384")) {
        cryptoKey = await jose.importPKCS8(pem, "ES384");
        return cryptoKey;
      }
      if (key.alg.includes("521")) {
        cryptoKey = await jose.importPKCS8(pem, "ES512");
        return cryptoKey;
      }
      if (key.alg == "secp256k1") {
        cryptoKey = await jose.importPKCS8(pem, "ES256K");
        return cryptoKey;
      }
      if (key.alg.includes("256")) {
        cryptoKey = await jose.importPKCS8(pem, "ES256");
        return cryptoKey;
      }
      throw TypeError(`Unsupported alg ${key.alg}`);
    }
    cryptoKey = await jose.importPKCS8(pem, `PS${hash}`);
    return cryptoKey;
  }
  const jwk = {
    kty: "RSA",
    n: key.getUint8(1).toB64Url(),
    e: key.getUint8(2).toB64Url(),
    d: key.getUint8(3).toB64Url(),
    p: key.getUint8(4).toB64Url(),
    q: key.getUint8(5).toB64Url(),
    dp: key.getUint8(6).toB64Url(),
    dq: key.getUint8(7).toB64Url(),
    qi: key.getUint8(8).toB64Url()
  };
  cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSA-PSS",
      hash: `SHA-${hash}`
    },
    true,
    ["sign"]
  );
  return cryptoKey;
}
function extractKey(asn1) {
  const asn1tocheck = asn1;
  while (true) {
    const types = Defs.commonTypes.map((type) => {
      const stats = Defs.match(asn1tocheck, type);
      return { type, match: stats.recognized / stats.total };
    }).sort((a, b) => b.match - a.match);
    Defs.match(asn1tocheck, types[0].type);
    return asn1tocheck;
  }
}
function parseKey(asn1) {
  const asn1Object = extractKey(asn1);
  const type = asn1Object.def.description;
  if (["PKCS#8 private key", "PKCS#1 RSA private key"].includes(type) !== true)
    throw Error("RSA Private Key is not found");
  if (asn1Object.def.description == "PKCS#8 private key") {
    Defs.match(asn1Object.sub[2].sub[0], Defs.commonTypes[3].type);
    asn1Object.sequence = asn1Object.sub[2].sub[0].sub;
    asn1Object.type = "PKCS#8";
    const [_oid0, name0, _format0] = asn1Object.sub[1].sub[0].content()?.split("\n") ?? [0, 0, 0];
    const [_oid1, name1, _format1] = asn1Object.sub[1].sub[1].content()?.split("\n") ?? [0, 0, 0];
    asn1Object.alg = name1;
    asn1Object.name = name0;
  }
  if (asn1Object.def.description == "PKCS#1 RSA private key") {
    asn1Object.sequence = asn1Object.sub;
    asn1Object.type = "PKCS#1";
  }
  asn1Object.getContent = getContent.bind(asn1Object);
  asn1Object.getUint8 = getUint8.bind(asn1Object);
  return asn1Object;
  function getContent(index = 0) {
    const { header, length, stream: { enc, pos } } = this.sequence[index];
    const end = pos + header + length;
    const start = pos + header;
    const values = Array.from(enc.subarray(start, end), (e) => Number(e).toString(16).padStart(2, "0")).join("");
    const _bin = BigInt("0x" + values);
    return _bin;
  }
}
function getUint8(index = 0) {
  const { header, length, stream: { enc, pos } } = this.sequence[index];
  const end = pos + header + length;
  const start = pos + header;
  return {
    toB64Url() {
      const base64 = btoa(String.fromCharCode(...Uint8Array.from(enc.slice(start, end))));
      return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    },
    raw() {
      return Uint8Array.from(enc.slice(start, end));
    }
  };
}
export {
  pem2key
};
