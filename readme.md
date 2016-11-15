# Angular WebCrypto

Angular bindings and XHR for Web Cryptography API.

More information about "Web Crypto API":

- [World Wide Web Consortium (W3C)](https://www.w3.org/TR/WebCryptoAPI/)
- [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [WebCrypto by The Chromium Project](https://www.chromium.org/blink/webcrypto)

## Features

- Full AngularJS module integration.
- Name based key storage for avoiding direct crypto objects access.
- Latests key exchange and encrypting algorithms.
- Native browser's "Web Crypto API" usage for maximum performance.
- $http -like service for automatic encrypt and decrypt XHR data (requires a server-side implementation).

## Requirements

- Web Cryptography API compatible browser, [check this list](http://caniuse.com/#feat=cryptography).
- AngularJS

Please note that this does not work with MS IE and will never be. 
Using on MS Edge browser has not been tested and its likely to not work since Edge does not support ECDH.

## Building from source

1. Clone
2. Install dependencies
    
    Install gulp-cli only if you don't have it already.
    ```bash
    $ sudo npm install --global gulp-cli
    $ npm install
    ```
3. Build
    ```bash
    $ gulp
    ```

    Output is in the dist folder.

## Installation

```
bower install angular-web-crypto --save-dev
```

```html
<!-- You can also use the ES6 version, but I recommend ES5 for best compatibility. -->
<script src="bower_components/angular-web-crypto/dist/ng-web-crypto.es5.min.js"></script>
```

## ECDH Key Agreement, Encryption and Decryption

Create your Elliptic Curve Diffie-Hellman private key.

```javascript
// This code is intended to be used in the module (application) configuration.
angular.module('YourApp', ['ngWebCrypto'])
.config(function($webCryptoProvider) {
    //Generate your private key and set as default.
    $webCryptoProvider.generateKey({
            name: 'myAppKey'
    }).success(
        function(keyName) {
            console.log('Key Generated!');
        }
    )
})
```

Import other party public raw key. The key must be encoded in Hexadecimal String. 

```javascript
// This code is intended to be used in a "service", "controller" or even a "directive".
angular.module('YourApp')
.controller('YourController', function($webCrypto) {
    // If you have in ArrayBuffer format, convert first to Uint8Array.
    // var keyInUint8Array = new Uint8Array(keyArrayBuffer);
    // then convert Uint8Array to HexString
    // var exportedKeyInHexaString = $webCrypto.tools.ArrayBufferToHexString(keyInUint8Array);
    $webCrypto.importAndDeriveWithDefaultKey(exportedKeyInHexaString)
    .success(
        function(derivedKeyName) {
            console.log('Key derived successfully.');
            // Now you can encrypt and decrypt.
            // encrypt test:
            $webCrypto.encrypt(derivedKeyName, "MY DATA TO BE ENCRYPTED")
            .success(
                function(encryptedData, iv) {
                    // The data is now encrypted in encryptedData, the IV has been stored in the IV
                    // variable, both of them has been converted to HexString for easy transport.
                    console.log('The data has been encrypted successfully.');
                    console.log('encrypted data:', encryptedData);
                    console.log('initialization vector:', iv);
                    // decrypt test:
                    $webCrypto.decrypt(derivedKeyName,encryptedData,iv)
                    .success(
                        function(decryptedData) {
                            // The data has been decrypted now
                            console.log('The data has been decrypted successfully.');
                            console.log('decrypted data:', decryptedData);
                        }
                    )
                    
                }
            )
        }
    )
})
```

## Working example

```javascript
angular.module('YourApp')
.controller('YourController', function($webCrypto) {
    //Generate your ECDH private key using a shortcut function.
    $webCrypto.generate({name: 'alice'})
    .success(
        function(aliceKeyName) {
            //Here you can export alice's public key to send to "bob" so he can also agree the keys.
            var alicePublicKey = $webCrypto.export(aliceKeyName);
            //Generate another ECDH private key (we will use the public part of this one)
            $webCrypto.generate({name: 'bob'})
            .success(
                function(bobKeyName) {
                    //We will export the bob's public key.
                    var bobPublicKey = $webCrypto.export(bobKeyName);
                    //Now we will import the bob's public key and derive with alice's to generate
                    //a RSA-GCM key for encrypting and decrypting.
                    $webCrypto.importAndDerive(aliceKeyName, bobPublicKey)
                    .success(
                        function(cryptoKeyName) {
                            //Now we have the CryptoKey that we can use to encrypt and decrypt data.
                            $webCrypto.encrypt(cryptoKeyName, 'Hello Bob, how you doing?')
                            .success(
                                function(encrypted, iv) {
                                    //The string has now been encrypted, we will show this to the console.
                                    //This format (HexString) is safe for XHR and plain text.
                                    console.log('encrypted', encrypted);
                                    //We will decode it, just for fun
                                    var decoded = $webCrypto.tools.HexStringToArrayBuffer(encrypted);
                                    console.log('encrypted (decoded)', decoded);
                                    //Now we will convert to string, also just for fun
                                    var decoded_string = $webCrypto.tools.ArrayBufferToString(decoded);
                                    console.log('encrypted (as string)', decoded_string);
                                    //Now we will decrypt the data
                                    $webCrypto.decrypt(cryptoKeyName, encrypted, iv)
                                    .success(
                                        function(decrypted) {
                                            //The data has been decrypted and converted to string
                                            console.log('decrypted', decrypted);
                                        }
                                    )
                                }
                            )
                        }
                    )
                }
            )
        }
    );
});    
```

## Encrypting & Decrypting JSON objects

Just convert your JSON objects to String using JSON.stringify before encrypting and JSON.parse after decrypting.

## FAQ

- Why all output is HexString encoded?

    Hex String is a highly portable encoding and safe for transport in any encoding (ASCII, UTF-8, etc.)

- Why the $httpCrypto service does not support the GET method?

    Using the GET method lowers the security of the transporting data.

## Work in progress

This library is in current development but **core functionalities** are working without issues and are unlikely to be modified. More extended features are comming soon.

## Docs

Documentation will be soon available, for now you can try to read the source file, its very clear.

## License

The MIT License (MIT)

Copyright ©2016 Giancarlo Chiappe Aguilar

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.