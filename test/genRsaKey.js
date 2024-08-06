import * as jose from 'npm:jose'

const hashs = Object.freeze({
   256: 'SHA-256',
   384: 'SHA-384',
   512: 'SHA-512'
})

const rsas = Object.freeze({
   'SSA': 'RSASSA-PKCS1-v1_5',
   'PSS': 'RSA-PSS',
   'OAEP': 'RSA-OAEP'
})

async function genRsaKey(type = 'PSS', modLen = 2048, hash = 256) {
   if (Object.prototype.hasOwnProperty.call(rsas, type) == false) throw TypeError('Invalid RSA type')
   if (modLen < 2048) throw TypeError(`Modulus length at least 2048`);
   if (Object.prototype.hasOwnProperty.call(hashs, hash) == false) throw TypeError('Invalid hash length')
   const key = await crypto.subtle.generateKey(
      {
         name: rsas[type],
         modulusLength: modLen,
         publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
         hash: hashs[hash]
      },
      true,
      ['sign', 'verify'],
   )
   return key
}

const RsaSsaKey = await genRsaKey('SSA');
const RsaPssKey = await genRsaKey('PSS');

const RsaSsaPem = await jose.exportPKCS8(RsaSsaKey.privateKey)
const RsaPssPem = await jose.exportPKCS8(RsaPssKey.privateKey)




