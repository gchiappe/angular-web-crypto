/*
ngWebCrypto
---
The MIT License (MIT)

copyright ©2016 Giancarlo A. Chiappe Aguilar

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished to do 
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE.
---
©2016 Giancarlo Chiappe Aguilar <gchiappe@outlook.com.pe>
*/
'use strict';
var NgWebCryptoUtils = (() => {
    function NgWebCryptoUtils() {
        this.ABtoString = (buffer) => String.fromCharCode.apply(null, buffer);
        // var str = "";
        // for (var iii = 0; iii < buffer.byteLength; iii++) {
        //     str += String.fromCharCode(buffer[iii]);
        // }
        // return str;
        //};
        this.StringtoAB = (str) => {
            var bytes = new Uint8Array(str.length);
            for (var iii = 0; iii < str.length; iii++) {
                bytes[iii] = str.charCodeAt(iii);
            }
            return bytes;
        };
        this.isFunction = (obj) => (!!(obj && obj.constructor && obj.call && obj.apply));
        this.isDefined = (variable) => {
            if (typeof variable === 'undefined' || variable === null) {
                return false;
            }
            return true;
        }
        this.ABToHS = (uint8arr) => {
            if (!uint8arr) {
                return '';
            }
            var hexStr = '';
            for (var i = 0; i < uint8arr.length; i++) {
                var hex = (uint8arr[i] & 0xff).toString(16);
                hex = (hex.length === 1) ? '0' + hex : hex;
                hexStr += hex;
            }
            return hexStr.toUpperCase();
        }
        this.HSToAB = (str) => {
            if (!str) {
                return new Uint8Array();
            }
            var a = [];
            for (var i = 0, len = str.length; i < len; i += 2) {
                a.push(parseInt(str.substr(i, 2), 16));
            }
            return new Uint8Array(a);
        }
    }
    return NgWebCryptoUtils;
})();
const webCryptoConstants = {
    class: {
        ECDH: 'ECDH',
        AESGCM: 'AES-GCM'
    },
    namedCurve: {
        P128: 'P-128',
        P256: 'P-256',
        P521: 'P-521'
    },
    format: {
        RAW: 'raw',
        JWK: 'jwk'
    },
    type: {
        PRIVATE: 'private',
        PUBLIC: 'public',
        MIXED: 'mixed'
    }
}
angular.module('ngWebCrypto', []);
angular.module('ngWebCrypto')
    .provider('$webCrypto', function ($injector) {
        var crypto = window.crypto;
        if (!crypto.subtle) {
            throw 'ng-web-crypto: browser not supported.';
        }
        var tools = $injector.instantiate(NgWebCryptoUtils);
        //almacenes: almacenar los cripto-objetos en variables de una funcion anonima.
        var keys = []; // llaves ECDH
        var cryptoKeys = []; // llaves criptograficas (def. AES-GCM)
        // llaves ECDH
        var getKey = (kName) => {
            for (let c = 0; c < keys.length; c++) {
                if (keys[c].name == kName) {
                    return keys[c];
                }
            }
            return -1;
        }
        // llaves AES
        var getCryptoKey = (kName) => {
            for (var c = 0; c < cryptoKeys.length; c++) {
                if (cryptoKeys[c].name == kName) {
                    return cryptoKeys[c];
                }
            }
            return -1;
        }
        var defaultKey = null, defaultCryptoKey = null;
        // Funciones del proveedor:
        this.generateKey = (options) => {
            if (tools.isDefined(options.random)) {
                if (options.random) {
                    options.name = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                }
            }
            if (!tools.isDefined(options.name)) { throw 'key name is required for generating.'; }
            if (getKey(options.name) != -1) { throw 'key name "', options.name, '" already in use.'; }
            if (!tools.isDefined(options.namedCurve)) { options.namedCurve = webCryptoConstants.namedCurve.P256 }
            if (!tools.isDefined(options.type)) { options.type = webCryptoConstants.type.PRIVATE }
            if (!(options.type == webCryptoConstants.type.PRIVATE ||
                options.type == webCryptoConstants.type.PUBLIC ||
                options.type == webCryptoConstants.type.MIXED)) {
                throw 'invalid key type (private, public, mixed).';
            }
            // == Crear Promesa
            var promise = new Promise((resolve, reject) => {
                // == Crear Llave
                crypto.subtle.generateKey({
                    name: webCryptoConstants.class.ECDH,
                    namedCurve: options.namedCurve
                },
                    true,
                    ['deriveKey', 'deriveBits'])
                    .then(
                    (key) => {
                        crypto.subtle.exportKey(webCryptoConstants.format.JWK, key.publicKey).then(
                            (eJwk) => {
                                crypto.subtle.exportKey(webCryptoConstants.format.RAW, key.publicKey).then(
                                    (eRaw) => {
                                        keys.push({
                                            class: webCryptoConstants.class.ECDH,
                                            type: options.type,
                                            name: options.name,
                                            key,
                                            jwk: eJwk,
                                            raw: eRaw
                                        });
                                        if (getKey(options.name) != -1) {
                                            if (!tools.isDefined(defaultKey)) defaultKey = options.name;
                                            resolve(options.name);
                                        } else {
                                            reject('key was not added to storage.');
                                        }
                                    }
                                )
                            }
                        )
                    }
                    )
                    .catch((err) => { reject(err); });
            });
            promise.success = (fn) => {
                promise.then((name) => { fn(name); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        }
        this.getDefaultKeys = () => ({
            ecdh: defaultKey,
            crypto: defaultCryptoKey
        })
        this.checkKey = (kName) => (getKey(kName) != -1);
        this.checkCryptoKey = (kName) => (getCryptoKey(kName) != -1);
        this.importKey = (options) => {
            if (!tools.isDefined(options.name)) { throw 'key name is required for importing.'; }
            if (this.checkKey(options.name)) { throw 'key name "', options.name, '" already in use.'; }
            if (!tools.isDefined(options.class)) options.class = webCryptoConstants.class.ECDH;
            if (!tools.isDefined(options.crv)) options.crv = webCryptoConstants.namedCurve.P256;
            if (!tools.isDefined(options.format)) options.format = webCryptoConstants.format.RAW;
            if (!tools.isDefined(options.type)) options.type = webCryptoConstants.type.PUBLIC;
            let importDataObj, algorithmDataObj;
            let keyCapabilities = [];
            console.log('format', options.format, 'class', options.class);
            if (options.format == webCryptoConstants.format.JWK) {
                if (options.class == webCryptoConstants.class.ECDH) {
                    if (!tools.isDefined(options.x) ||
                        !tools.isDefined(options.y) ||
                        !tools.isDefined(options.d)) {
                        throw 'x, y and d parameters are required to import an ECDH key.';
                    }
                    importDataObj = {
                        kty: 'EC',
                        crv: options.crv,
                        x: options.x,
                        y: options.y,
                        d: options.d,
                        ext: true
                    }
                    algorithmDataObj = {
                        name: webCryptoConstants.class.ECDH,
                        namedCurve: options.crv
                    }
                    if (options.type == webCryptoConstants.type.PRIVATE)
                        keyCapabilities = ['deriveKey', 'deriveBits'];    
                } else if (options.class == webCryptoConstants.class.AESGCM) {
                    if (!tools.isDefined(options.k)) {
                        throw 'k parameter is required to import an AES-GCM key (k paramter must be HexString encoded).'
                    }
                    // console.log('key', tools.HSToAB(options.k));
                    // console.log('key (String)', btoa(tools.ABtoString(tools.HSToAB(options.k))).slice(0,-1) );
                    importDataObj = {
                        kty: 'oct',
                        k: btoa(tools.ABtoString(tools.HSToAB(options.k))).slice(0,-1), // HexString -> Uint8Array -> String -> Base64 -> Remove Last Char.
                        alg: 'A256GCM',
                        ext: true
                    }
                    algorithmDataObj = {
                        name: webCryptoConstants.class.AESGCM
                    }
                    keyCapabilities = ['encrypt', 'decrypt'];
                } else {
                    throw 'unsupported crypto class';
                }                                
            } else {
                if (!tools.isDefined(options.raw)) {
                    throw 'raw parameter is missing.';
                }
                importDataObj = tools.HSToAB(options.raw);
                if (options.class == webCryptoConstants.class.ECDH) {
                    algorithmDataObj = {
                        name: webCryptoConstants.class.ECDH,
                        namedCurve: options.crv
                    }
                } else if (options.class == webCryptoConstants.class.AESGCM) {
                    algorithmDataObj = {
                        name: webCryptoConstants.class.AESGCM
                    }
                } else {
                    throw 'unsupported crypto class';
                }
            }
            // console.log('algo data obj', algorithmDataObj);
            // console.log('import obj', importDataObj);
            var promise = new Promise((resolve, reject) => {
                crypto.subtle.importKey(
                    options.format,
                    importDataObj,
                    algorithmDataObj,
                    true,
                    keyCapabilities
                )
                    .then((key) => {
                        crypto.subtle.exportKey('jwk', key).then(
                            (eJwk) => {
                                crypto.subtle.exportKey('raw', key).then(
                                    (eRaw) => {
                                        keys.push({
                                            class: options.class,
                                            type: options.type,
                                            name: options.name,
                                            key: { publicKey: key },
                                            jwk: eJwk,
                                            raw: eRaw
                                        });
                                        if (getKey(options.name) != -1) {
                                            resolve(options.name);
                                        } else {
                                            reject('key was not added to storage.');
                                        }
                                    }
                                )
                            }
                        )
                    })
                    .catch((err) => {
                        reject('error catched.');
                        throw err;
                    });
            });
            promise.success = (fn) => {
                promise.then((name) => { fn(name); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        }
        this.exportKey = (options) => {
            // == Chequeo
            if (tools.isDefined(options.default)) {
                if (options.default)
                    if (tools.isDefined(defaultKey)) {
                        options.name = defaultKey;
                    } else {
                        throw 'default key is not defined.';
                    }
            }
            if (!tools.isDefined(options.name)) {
                throw 'key name is required for exporting keys.';
            }
            // == Obtener la llave y verificarla.
            var theKey = getKey(options.name);
            if (theKey == -1) {
                throw 'Key "', options.name, '" not found.';
            }
            // == Defectos
            if (!tools.isDefined(options.type)) {
                options.type = webCryptoConstants.format.RAW;
            }
            if (options.type == webCryptoConstants.format.JWK)
                if (tools.isDefined(theKey.jwk))
                    return theKey.jwk;
                else {
                    throw 'the key "', options.name, '" cannot be exported.';
                }
            else if (options.type == webCryptoConstants.format.RAW)
                if (tools.isDefined(theKey.raw))
                    return tools.ABToHS(new Uint8Array(theKey.raw));
                else {
                    throw 'the key "', options.name, '" cannot be exported.';
                }
            else {
                throw 'invalid export type';
            }
        }
        this.deriveBits = (options) => {
            // == Chequeo de errores.
            if (!tools.isDefined(options.privateKeyName) ||
                !tools.isDefined(options.publicKeyName)) {
                throw 'deriving bits require two previously stored keys.';
            }
            // == Obtener las llaves y verificarlas.   
            var privateKey = getKey(options.privateKeyName), publicKey = getKey(options.publicKeyName);
            if (privateKey == -1) { throw 'private key "', options.privateKeyName, '" not found.'; }
            if (publicKey == -1) { throw 'public key "', options.publicKeyName, '" not found.'; }
            if (privateKey.type != 'mixed') {
                if (privateKey.type != 'private') { throw 'key "', options.privateKeyName, '" is not a valid private key.'; }
                if (publicKey.type != 'public') { throw 'key "', options.publicKeyName, '" is not a valid public key.'; }
            }
            // == Establecer defectos si no se han definido.            
            if (!tools.isDefined(options.bits)) { options.bits = 256; }
            if (!tools.isDefined(options.format)) { options.format = 'HS'; }
            if (!tools.isDefined(options.namedCurve)) { options.namedCurve = webCryptoConstants.namedCurve.P256; }
            // == Derivacion
            var promise = new Promise((resolve, reject) => {
                crypto.subtle.deriveBits(
                    {
                        name: webCryptoConstants.class.ECDH,
                        namedCurve: options.namedCurve,
                        public: publicKey.key.publicKey
                    },
                    privateKey.key.privateKey,
                    options.bits
                )
                    .then((bits) => {
                        let out = new Uint8Array(bits);
                        resolve(tools.ABToHS(new Uint8Array(bits)));
                    })
                    .catch((err) => {
                        console.error('error deriving bits: ', err, '.');
                        reject(err);
                    });
            });
            promise.success = (fn) => {
                promise.then((name) => { fn(name); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        }
        this.deriveKey = (options) => {
            // == Chequeo de errores.
            if (!tools.isDefined(options.name)) { throw 'key name is required for deriving ECDH keys.'; }
            if (getCryptoKey(options.name) != -1) { throw 'key name "', options.name, '" already in use.'; }
            if (!tools.isDefined(options.privateKeyName) ||
                !tools.isDefined(options.publicKeyName)) {
                throw 'deriving keys require two previously stored keys.';
            }
            // == Obtener las llaves y verificarlas.   
            var privateKey = getKey(options.privateKeyName), publicKey = getKey(options.publicKeyName);
            if (privateKey == -1) { throw 'private key "', options.privateKeyName, '" not found.'; }
            if (publicKey == -1) { throw 'public key "', options.publicKeyName, '" not found.'; }
            if (privateKey.type != 'mixed') {
                if (privateKey.type != 'private') { throw 'key "', options.privateKeyName, '" is not a valid private key.'; }
                if (publicKey.type != 'public') { throw 'key "', options.publicKeyName, '" is not a valid public key.'; }
            }
            // == Establecer defectos si no se han definido.            
            if (!tools.isDefined(options.targetClass)) { options.targetClass = 'AES-GCM'; }
            if (!tools.isDefined(options.targetLength)) { options.targetLength = 256; }
            if (!tools.isDefined(options.namedCurve)) { options.namedCurve = 'P-256'; }
            if (!tools.isDefined(options.exportable)) { options.exportable = false; }
            // == Derivacion
            var promise = new Promise((resolve, reject) => {
                crypto.subtle.deriveKey(
                    {
                        name: 'ECDH',
                        namedCurve: options.namedCurve,
                        public: publicKey.key.publicKey
                    },
                    privateKey.key.privateKey,
                    {
                        name: options.targetClass,
                        length: options.targetLength
                    },
                    options.exportable,
                    ['encrypt', 'decrypt'])
                    .then((key) => {
                        key = { publicKey: key };
                        if (options.exportable) {
                            crypto.subtle.exportKey('jwk', key.publicKey).then((eJwk) => {
                                crypto.subtle.exportKey('raw', key.publicKey).then((eRaw) => {
                                    cryptoKeys.push({
                                        class: options.targetClass,
                                        type: 'private',
                                        name: options.name,
                                        key: key,
                                        jwk: eJwk,
                                        raw: eRaw
                                    });
                                    if (getCryptoKey(options.name) != -1) {
                                        if (!tools.isDefined(defaultCryptoKey)) defaultCryptoKey = options.name;
                                        resolve(options.name);
                                    } else {
                                        reject('key was not added to storage.');
                                    }
                                })
                            }
                            )
                                .catch((err) => {
                                    console.error('error exporting derived key: ', err, '.');
                                    reject(err);
                                });
                        } else {
                            cryptoKeys.push({
                                class: options.targetClass,
                                type: 'private',
                                name: options.name,
                                key: key,
                                jwk: null,
                                raw: null
                            });
                            if (getCryptoKey(options.name) != -1) {
                                if (!tools.isDefined(defaultCryptoKey)) defaultCryptoKey = options.name;
                                resolve(options.name);
                            } else {
                                reject('key was not added to storage.');
                            }
                        }
                    })
                    .catch((err) => {
                        console.log('error deriving key: ', err, '.');
                        reject(err);
                    });
            });
            promise.success = (fn) => {
                promise.then((name) => { fn(name); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        };
        this.encrypt = function (options) {
            if (tools.isDefined(options.default)) {
                if (options.default)
                    if (tools.isDefined(defaultCryptoKey)) { options.name = defaultCryptoKey; }
                    else { throw 'default key is not defined.'; }
            }
            // == Verificacion de errores
            if (!tools.isDefined(options.name)) { throw 'key name is required for deriving ECDH keys.'; }
            if (!tools.isDefined(options.data)) { throw 'data option must be defined and not null.'; }
            // == Obtener llave
            if (getCryptoKey(options.name) == -1) { throw 'Key "', options.name, '" not found.'; }
            // == Validar capacidad de la llave
            if (getCryptoKey(options.name).class == 'ECDH') { throw 'Key "', options.name, '" is not valid for encryption.'; }
            // == Defectos
            if (!tools.isDefined(options.tagLength)) { options.tagLength = 128; }
            // == IV (vector de inicializacion)
            var encIV = crypto.getRandomValues(new Uint8Array(12));
            // == Promesa
            var promise = new Promise((resolve, reject) => {
                // == Cifrar
                crypto.subtle.encrypt(
                    {
                        name: getCryptoKey(options.name).class,
                        iv: encIV,
                        tagLength: options.tagLength
                    },
                    getCryptoKey(options.name).key.publicKey,
                    tools.StringtoAB(options.data)
                )
                    .then((encrypted) => {
                        console.log('enc success');
                        var data = {
                            encrypted: tools.ABToHS(new Uint8Array(encrypted)),
                            iv: tools.ABToHS(encIV)
                        };
                        // == Ejecutar promesa
                        resolve(data);
                    })
                    .catch((err) => {
                        reject(err);
                        throw err;
                    });
            });
            promise.success = (fn) => {
                promise.then((data) => { fn(data.encrypted, data.iv); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        };
        this.decrypt = (options) => {
            // == Comprobar si se va a usar la llave criptográfica por defecto.
            if (tools.isDefined(options.default)) {
                if (options.default)
                    if (tools.isDefined(defaultCryptoKey)) { options.name = defaultCryptoKey; }
                    else { throw 'default key is not defined.'; }
            }
            // == Comprobacion
            if (!tools.isDefined(options.name)) { throw 'key name is required for decrypting.'; }
            if (!tools.isDefined(options.iv)) { throw 'the iv is required for decrypting.'; }
            if (!tools.isDefined(options.data)) { throw 'data option must be defined and not null.'; }
            // == Obtener llave
            if (getCryptoKey(options.name) == -1) { throw 'Key "', options.name, '" not found.'; }
            // == Validar capacidad de la llave
            if (getCryptoKey(options.name).class == 'ECDH') { throw 'Key "', options.name, '" is not valid for encryption.'; }
            // == Defectos
            if (!tools.isDefined(options.tagLength)) { options.tagLength = 128; }
            var promise = new Promise((resolve, reject) => {
                crypto.subtle.decrypt({ name: getCryptoKey(options.name).class, iv: tools.HSToAB(options.iv), tagLength: options.tagLength },
                    getCryptoKey(options.name).key.publicKey,
                    tools.HSToAB(options.data))
                    .then((ec) => {
                        data = { decrypted: tools.ABtoString(new Uint8Array(dec)) }
                        resolve(data);
                    })
                    .catch((err) => { reject(err); })
            });
            promise.success = (fn) => {
                promise.then(function (data) { fn(data.decrypted); });
                return promise;
            }
            promise.error = (fn) => {
                promise.then(null, (name) => { fn(name); });
                return promise;
            }
            return promise;
        };
        // == Servicio
        this.$get = () => {
            return {
                //Acceso público a herramientas
                tools: {
                    ArrayBufferToHexString: (ab) => tools.ABToHS(ab),
                    HexStringToArrayBuffer: (hs) => tools.HSToAB(hs),
                    ArrayBufferToString: (ab) => tools.ABtoString(ab),
                    StringToArrayBuffer: (str) => tools.StringtoAB(str)
                },
                //Acceso público a la generación de llaves
                generate: (options) => this.generateKey(options),
                //Genera una nueva llave AES-GCM en base a una semilla (obtenida de deriveBits)
                generateWithSeed: (seed) => this.importKey({ 
                    name: tools.ABToHS(crypto.getRandomValues(new Uint8Array(12))), 
                    k: seed, 
                    class: webCryptoConstants.class.AESGCM, 
                    format: webCryptoConstants.format.JWK }),
                //Importar llave pública
                import: (raw) => this.importKey({ name: tools.ABToHS(crypto.getRandomValues(new Uint8Array(12))), raw: raw }),                
                //Importar llave pública y derivar con la llave privada por defecto para generar una criptollave.
                importAndDeriveWithDefaultKey: (raw) => {
                    var _provider = this;
                    var defKeys = _provider.getDefaultKeys();
                    var importName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                    var rsaKeyName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                    if (tools.isDefined(defKeys.ecdh)) {
                        var promise = new Promise((resolve, reject) => {
                            _provider.importKey({ name: importName, raw: raw })
                                .success((importedKeyName) => {
                                    _provider.deriveKey({ name: rsaKeyName, privateKeyName: defKeys.ecdh, publicKeyName: importedKeyName })
                                        .success((derivedKeyName) => { resolve(derivedKeyName); });
                                });
                        });
                        promise.success = (fn) => {
                            promise.then((data) => { fn(data); });
                            return promise;
                        }
                        promise.error = (fn) => {
                            promise.then(null, (name) => { fn(name); });
                            return promise;
                        }
                        return promise;
                    } else {
                        console.error('No default ECDH key defined.');
                    }
                },
                //Importar y derivar contra una llave privada almacenada.
                importAndDerive: (name, raw) => {
                    var _provider = this;
                    var importName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                    var rsaKeyName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                    var promise = new Promise((resolve, reject) => {
                        _provider.importKey({ name: importName, raw: raw })
                            .success((importedKeyName) => {
                                _provider.deriveKey({ name: rsaKeyName, privateKeyName: name, publicKeyName: importedKeyName })
                                    .success((derivedKeyName) => { resolve(derivedKeyName); });
                            });
                    });
                    promise.success = (fn) => {
                        promise.then((data) => { fn(data) });
                        return promise;
                    }
                    promise.error = (fn) => {
                        promise.then(null, (name) => { fn(name); });
                        return promise;
                    }
                    return promise;
                },
                //Importa y crea semilla para importar llave AES-GCM.
                importAndDeriveBits: (name, raw) => {
                    var _provider = this;
                    var importName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                    var promise = new Promise((resolve, reject) => {
                        _provider.importKey({ name: importName, raw})
                        .success((importedKeyName) => {
                            _provider.deriveBits({
                                privateKeyName: name,
                                publicKeyName: importedKeyName
                            })
                            .success((bits) => { resolve(bits) });
                        })
                    });
                    promise.success = (fn) => {
                        promise.then((data) => { fn(data) });
                        return promise;
                    }
                    promise.error = (fn) => {
                        promise.then(null, (name) => { fn(name); });
                        return promise;
                    }
                    return promise;
                },
                //Accesos públicos y short-cuts.
                export: (name) => this.exportKey({ name }),
                exportDefaultKey: () => this.exportKey({ default: true }),
                encrypt: (name, data) => this.encrypt({ name, data }),
                decrypt: (name, data, iv) => this.decrypt({ name, data, iv }),
                encryptWithDefaultKey: (data) => this.encrypt({ default: true, data }),
                decryptWithDefaultKey: (data, iv) => this.decrypt({ default: true, data, iv }),
                getDefaultKeys: () => this.getDefaultKeys(),
                checkCryptoKey: (key) => this.checkCryptoKey(key),
                checkKey: (key) => this.checkKey(key)
            }
        }
    })
    .factory('$httpCrypto', function ($webCrypto, $http, $injector) {
        //This service is a WIP part, not tested but should be functional, requires a compatible
        //server.
        var tools = $injector.instantiate(NgWebCryptoUtils);
        return {
            post: function (server, data, key = null) {
                if (!tools.isDefined(server)) {
                    console.error('please define "server" in the options.');
                    return;
                }
                if (!tools.isDefined(data)) {
                    data = {};
                }
                if (!tools.isDefined(key)) {
                    key = $webCrypto.getDefaultKeys().crypto;
                    if (!tools.isDefined(key)) {
                        console.error('default crypto key is not defined');
                        return;
                    }
                }
                if (!$webCrypto.checkCryptoKey(key)) {
                    console.error('key "', key, '" not found.');
                    return;
                }
                var ucdata_str = JSON.stringify(data);
                var promise = new Promise(
                    (resolve, reject) => {
                        $webCrypto.encrypt(key, ucdata_str)
                            .success(
                            (encrypted, iv) => {
                                var encData = {
                                    data: encrypted,
                                    iv
                                }
                                $http.post(
                                    server,
                                    {
                                        d: `${encrypted}.${iv}`                                        
                                    }
                                )
                                    .success(
                                    (rdata,
                                        status,
                                        headers,
                                        config,
                                        statusText) => {
                                        // == Validar respuesta
                                        if (!tools.isDefined(rdata.d)) {
                                            console.error('invalid crypto response from server.');
                                            reject(rdata);
                                            return;
                                        }
                                        if (rdata.d.indexOf(".") == -1) {
                                            console.error('invalid crypto response from server.');
                                            reject(rdata);
                                            return;
                                        }
                                        // == Parsear respuesta
                                        var rdatao = rdata.d.split('.')[0];
                                        var rivo = rdata.d.split('.')[1];
                                        // == Decifrar ahora
                                        $webCrypto.decrypt(key, rdatao, ivo)
                                            .success(
                                            decrypted => {
                                                try {
                                                    var parsed = JSON.parse(decrypted);
                                                } catch (e) {
                                                    console.error('decrypted response is not json.');
                                                    reject(decrypted);
                                                    return;
                                                }
                                                resultObj = {
                                                    data: parsed,
                                                    status,
                                                    headers,
                                                    config,
                                                    statusText,
                                                    encrypted: encData
                                                }
                                                resolve(resultObj);
                                            }
                                            )
                                            .error( (err) => {
                                                resultObj = {
                                                    data: null,
                                                    status,
                                                    headers,
                                                    config,
                                                    statusText,
                                                    encrypted: encData
                                                }
                                                reject(resultObj);
                                            })
                                    })
                                    .error( (rdata,
                                        status,
                                        headers,
                                        config,
                                        statusText) => {
                                        resultObj = {
                                            data: null,
                                            status,
                                            headers,
                                            config,
                                            statusText,
                                            encrypted: encData
                                        }
                                        reject(resultObj);
                                    });
                            })
                            .error( (err) => {
                                resultObj = {
                                    data: null,
                                    status: null,
                                    headers: null,
                                    config,
                                    statusText: null,
                                    encrypted: null
                                }
                                reject(resultObj);
                            });
                    });
                promise.success = (fn) => {
                    promise.then((p) => { fn(p.data); });
                    return promise;
                }
                promise.error = (fn) => {
                    promise.then(null, (name) => { fn(name); });
                    return promise;
                }
                return promise;
            }
        }
    });