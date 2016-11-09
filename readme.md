# Angular WebCrypto

Angular bindings and XHR for Web Cryptography API.

## Requirements

- ECMAScript 6 compatible browser, [check this list](http://kangax.github.io/compat-table/es6/).
- Web Cryptography API compatible browser, [check this list](http://caniuse.com/#feat=cryptography).

Most browsers that meet one requirement also meet the second one. Please note that this does not work
with IE and will never be. Using on MS Edge browser has not been tested but should work.

## ECDH Key Agreement, Encryption and Decryption

Create your Elliptic Curve Diffie-Hellman private key.

```javascript
angular.module('YourApp', 'ngWebCrypto')
.config(($webCryptoProvider) => {
    //Generate your private key and set as default.
    $webCryptoProvider.generateKey(
        {
            name: 'myAppKey'
        }
    ).success(
        keyName => {
            console.log('Key Generated!');
        }
    )
})
```

Import other party public raw key. The key must be encoded in Hexadecimal String. 

```javascript
angular.module('YourApp')
.controller('YourController',($webCrypto) => {
    // If you have in ArrayBuffer format, convert first to Uint8Array.
    // var keyInUint8Array = new Uint8Array(keyArrayBuffer);
    // then convert Uint8Array to HexString
    // var exportedKeyInHexaString = $webCrypto.tools.ArrayBufferToHexString(keyInUint8Array);
    $webCrypto.importAndDeriveWithDefaultKey(exportedKeyInHexaString)
    .success(
        derivedKeyName => {
            console.log('Key derived successfully.');
            // Now you can encrypt and decrypt.
            // encrypt test:
            $webCrypto.encrypt(derivedKeyName, "MY DATA TO BE ENCRYPTED")
            .success(
                (encryptedData, iv) => {
                    // The data is now encrypted in encryptedData, the IV has been stored in the IV
                    // variable, both of them has been converted to HexString for easy transport.
                    console.log('The data has been encrypted successfully.');
                    console.log('encrypted data:', encryptedData);
                    console.log('initialization vector:', iv);
                    // decrypt test:
                    $webCrypto.decrypt(derivedKeyName,encryptedData,iv)
                    .success(
                        decryptedData => {
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

Please note that the use of the $webCryptoProvider is only for
example purposes and it **should** be used at config time.

```javascript
angular.module('YourApp')
.controller('YourController',($webCryptoProvider, $webCrypto) => {
    //Generate your ECDH private key.
    $webCryptoProvider.generateKey({name: 'alice'})
    .success(
        aliceKeyName => {
            //Here you can export alice's public key to send to "bob" so he can also agree the keys.
            var alicePublicKey = $webCrypto.export(aliceKeyName);
            //Generate another ECDH private key (we will use the public part of this one)
            $webCryptoProvider.generateKey({name: 'bob'})
            .success(
                bobKeyName => {
                    //We will export the bob's public key.
                    var bobPublicKey = $webCrypto.export(bobKeyName);
                    //Now we will import the bob's public key and derive with alice's to generate
                    //a RSA-GCM key for encrypting and decrypting.
                    $webCrypto.importAndDerive(aliceKeyName, bobPublicKey)
                    .success(
                        cryptoKeyName => {
                            //Now we have the CryptoKey that we can use to encrypt and decrypt data.
                            $webCrypto.encrypt(cryptoKeyName, 'Hello Bob, how you doing?')
                            .success(
                                (encrypted, iv) => {
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
                                        decrypted => {
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

## Encrypting JSON objects

Just convert your JSON objects to String using JSON.stringify before encrypting and JSON.parse after decrypting.

## License

The MIT License (MIT)

Copyright ©2016 Giancarlo Chiappe Aguilar

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.