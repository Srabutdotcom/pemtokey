## pemtokey

**pemtokey** is a JavaScript library designed to efficiently parse private key from PEM strings into `CryptoKey` objects, ready for cryptographic operations.

### Usage

```javascript
import { pemtokey } from 'pem2key.js';

const pemString = '-----BEGIN PRIVATE KEY-----\n' +
                   'MIICXAIBAAKBgQDH... (your private key content)\n' +
                   '-----END PRIVATE KEY-----';

const privateKey = await pemtokey(pemString, 256)
```

### Arguments

* `pemString`: The PEM-formatted private key string.
* `hash`: The desired hash algorithm. Supported values: 256, 384, or 512.

### Supported Key Formats

* Currently supports RSA and ECDSA private keys in PEM format.


### Contributing

Contributions to improve the library are welcome. Please open an issue or pull request on the GitHub repository.

### License
MIT
