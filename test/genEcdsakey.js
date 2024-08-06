import jwkToPem from 'npm:jwk-to-pem';
import * as jose from 'npm:jose'

const curveBits = Object.freeze({
   256:'P-256',
   384:'P-384',
   521:'P-521'
})

async function genEcdsaKey(curveBit){
   if(Object.prototype.hasOwnProperty.call(curveBits,curveBit)==false)throw TypeError('Invalid curveBit')
   const key = await crypto.subtle.generateKey(
      {
         name: 'ECDSA',
         namedCurve: curveBits[curveBit]
      },
      true,
      ['sign', 'verify'],
   )
   return key
}

const ecKeys = await genEcdsaKey(256);

async function exportEcKey2Jwk(key){
   const jwk = await crypto.subtle.exportKey('jwk',key);
   return jwk;
}

const ecJwk = await exportEcKey2Jwk(ecKeys.privateKey)
//const pem2 = await jose.exportPKCS8(ecKeys.privateKey)
const pem = jwkToPem(ecJwk, {private:true});


