# pem2key

A Deno module for extracting private keys from PEM strings and converting them into `CryptoKey` objects suitable for cryptographic operations.

## Usage

You can use the `pem2key` function to extract a private key from a PEM string and convert it to a `CryptoKey` object. The function supports various hash algorithms (256, 384, and 512).

### Example

```javascript
import { pem2key } from "jsr:@aicone/pem2key";

const pemString = `-----BEGIN PRIVATE KEY-----
<your-base64-private-key>
-----END PRIVATE KEY-----`;

const hash = 256; // Specify the hash algorithm (256, 384, or 512)

try {
    const cryptoKey = await pem2key(pemString, hash);
    console.log("CryptoKey generated:", cryptoKey);
} catch (error) {
    console.error("Error:", error);
}
```

## API

### `pem2key(pemstring: string, hash: number): Promise<CryptoKey>`

- **pemstring**: A base64 encoded PEM string containing a private key.
- **hash**: The hash algorithm to use, which can be either 256, 384, or 512.
- **Returns**: A Promise that resolves to a `CryptoKey` object.

### Errors

The function throws a `TypeError` if:
- The provided PEM string does not contain a valid private key.
- The specified hash algorithm is invalid.

## Key Formats

The module supports the following key formats:

- `PKCS#8`
- `PKCS#1`

### Supported Key Formats

* Currently supports RSA and ECDSA private keys in PEM format.

## Dependencies

This module depends on the following packages:

- [@lapo/asn1js](https://www.npmjs.com/package/@lapo/asn1js)
- [jose](https://github.com/panva/jose)

### Contributing

Contributions to improve the library are welcome. Please open an issue or pull request on the GitHub repository.

### Donation
- https://paypal.me/aiconeid 

### License

This project is licensed under the MIT License.
