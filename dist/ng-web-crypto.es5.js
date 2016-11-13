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

var NgWebCryptoUtils = function () {
    function NgWebCryptoUtils() {
        this.ABtoString = function (buffer) {
            var str = "";
            for (var iii = 0; iii < buffer.byteLength; iii++) {
                str += String.fromCharCode(buffer[iii]);
            }
            return str;
        };
        this.StringtoAB = function (str) {
            var bytes = new Uint8Array(str.length);
            for (var iii = 0; iii < str.length; iii++) {
                bytes[iii] = str.charCodeAt(iii);
            }
            return bytes;
        };
        this.isFunction = function (obj) {
            return !!(obj && obj.constructor && obj.call && obj.apply);
        };
        this.isDefined = function (variable) {
            if (typeof variable === 'undefined' || variable === null) {
                return false;
            }
            return true;
        };
        this.ABToHS = function (uint8arr) {
            if (!uint8arr) {
                return '';
            }
            var hexStr = '';
            for (var i = 0; i < uint8arr.length; i++) {
                var hex = (uint8arr[i] & 0xff).toString(16);
                hex = hex.length === 1 ? '0' + hex : hex;
                hexStr += hex;
            }
            return hexStr.toUpperCase();
        };
        this.HSToAB = function (str) {
            if (!str) {
                return new Uint8Array();
            }
            var a = [];
            for (var i = 0, len = str.length; i < len; i += 2) {
                a.push(parseInt(str.substr(i, 2), 16));
            }
            return new Uint8Array(a);
        };
    }
    return NgWebCryptoUtils;
}();
angular.module('ngWebCrypto', []);
angular.module('ngWebCrypto').provider('$webCrypto', function ($injector) {
    var _this = this;

    var crypto = window.crypto;
    if (!crypto.subtle) {
        throw 'ng-web-crypto: browser not supported.';
    }
    var tools = $injector.instantiate(NgWebCryptoUtils);
    //almacenes: almacenar los cripto-objetos en variables de una funcion anonima.
    var keys = []; // llaves ECDH
    var cryptoKeys = []; // llaves criptograficas (def. AES-GCM)
    // llaves ECDH
    var getKey = function getKey(kName) {
        for (var c = 0; c < keys.length; c++) {
            if (keys[c].name == kName) {
                return keys[c];
            }
        }
        return -1;
    };
    // llaves AES
    var getCryptoKey = function getCryptoKey(kName) {
        for (var c = 0; c < cryptoKeys.length; c++) {
            if (cryptoKeys[c].name == kName) {
                return cryptoKeys[c];
            }
        }
        return -1;
    };
    var defaultKey = null,
        defaultCryptoKey = null;
    // Funciones del proveedor:
    this.generateKey = function (options) {
        if (tools.isDefined(options.random)) {
            if (options.random) {
                options.name = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
            }
        }
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for generating.');
            return;
        }
        if (getKey(options.name) != -1) {
            console.error('key name "', options.name, '" already in use.');
            return;
        }
        if (!tools.isDefined(options.namedCurve)) {
            options.namedCurve = 'P-256';
        }
        if (!tools.isDefined(options.type)) {
            options.type = 'private';
        }
        if (!(options.type == 'private' || options.type == 'public' || options.type == 'mixed')) {
            console.error('invalid key type (private, public, mixed).');
            return;
        }
        // == Crear Promesa
        var promise = new Promise(function (resolve, reject) {
            // == Crear Llave
            crypto.subtle.generateKey({
                name: 'ECDH',
                namedCurve: options.namedCurve
            }, true, ['deriveKey', 'deriveBits']).then(function (key) {
                var gRaw, gJwk;
                crypto.subtle.exportKey('jwk', key.publicKey).then(function (eJwk) {
                    gJwk = eJwk;
                    crypto.subtle.exportKey('raw', key.publicKey).then(function (eRaw) {
                        gRaw = eRaw;
                        keys.push({
                            class: 'ECDH',
                            type: options.type,
                            name: options.name,
                            key: key,
                            jwk: gJwk,
                            raw: gRaw
                        });
                        if (getKey(options.name) != -1) {
                            if (!tools.isDefined(defaultKey)) defaultKey = options.name;
                            resolve(options.name);
                        } else {
                            reject('key was not added to storage.');
                        }
                    });
                });
            }).catch(function (err) {
                reject(err);
            });
        });
        promise.success = function (fn) {
            promise.then(function (name) {
                fn(name);
            });
            return promise;
        };
        promise.error = function (fn) {
            promise.then(null, function (name) {
                fn(name);
            });
            return promise;
        };
        return promise;
    };
    this.getDefaultKeys = function () {
        return {
            ecdh: defaultKey,
            crypto: defaultCryptoKey
        };
    };
    this.checkKey = function (kName) {
        return getKey(kName) != -1;
    };
    this.checkCryptoKey = function (kName) {
        return getCryptoKey(kName) != -1;
    };
    this.importKey = function (options) {
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for importing.');
            return;
        }
        if (_this.checkKey(options.name)) {
            console.error('key name "', options.name, '" already in use.');
            return;
        }
        if (!tools.isDefined(options.crv)) options.crv = 'P-256';
        if (!tools.isDefined(options.format)) options.format = 'raw';
        if (!tools.isDefined(options.type)) options.type = 'public';
        var importDataObj = void 0;
        var keyCapabilities = [];
        if (options.format == 'jwk') {
            if (!tools.isDefined(options.x) || !tools.isDefined(options.y) || !tools.isDefined(options.d)) {
                throw 'x, y and d parameters are required to import an ECDH key.';
            }
            importDataObj = {
                kty: 'EC',
                crv: options.crv,
                x: options.x,
                y: options.y,
                d: options.d,
                ext: true
            };
            if (options.type == 'private') keyCapabilities = ['deriveKey', 'deriveBits'];
        } else {
            if (!tools.isDefined(options.raw)) {
                throw 'raw parameter is missing.';
            }
            importDataObj = tools.HSToAB(options.raw);
        }
        var promise = new Promise(function (resolve, reject) {
            crypto.subtle.importKey(options.format, importDataObj, {
                name: 'ECDH',
                namedCurve: options.crv
            }, true, keyCapabilities).then(function (key) {
                var gRaw = void 0,
                    gJwk = void 0;
                crypto.subtle.exportKey('jwk', key).then(function (eJwk) {
                    gJwk = eJwk;
                    crypto.subtle.exportKey('raw', key).then(function (eRaw) {
                        gRaw = eRaw;
                        keys.push({
                            class: 'ECDH',
                            type: options.type,
                            name: options.name,
                            key: { publicKey: key },
                            jwk: gJwk,
                            raw: gRaw
                        });
                        if (getKey(options.name) != -1) {
                            resolve(options.name);
                        } else {
                            reject('key was not added to storage.');
                        }
                    });
                });
            }).catch(function (err) {
                reject('error catched.');
                throw err;
            });
        });
        promise.success = function (fn) {
            promise.then(function (name) {
                fn(name);
            });
            return promise;
        };
        promise.error = function (fn) {
            promise.then(null, function (name) {
                fn(name);
            });
            return promise;
        };
        return promise;
    };
    this.exportKey = function (options) {
        // == Chequeo
        if (tools.isDefined(options.default)) {
            if (options.default) if (tools.isDefined(defaultKey)) {
                options.name = defaultKey;
            } else {
                console.error('default key is not defined.');
                return;
            }
        }
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for exporting keys.');
            return;
        }
        if (getKey(options.name) == -1) {
            console.error('Key "', options.name, '" not found.');
            return;
        }
        // == Defectos
        if (!tools.isDefined(options.type)) {
            options.type = 'raw';
        }
        if (options.type == 'jwk') {
            if (tools.isDefined(getKey(options.name).jwk)) return getKey(options.name).jwk;else {
                console.error('the key "', options.name, '" cannot be exported.');
                return;
            }
        } else if (options.type == 'raw') {
            if (tools.isDefined(getKey(options.name).raw)) return tools.ABToHS(new Uint8Array(getKey(options.name).raw));else {
                console.error('the key "', options.name, '" cannot be exported.');
                return;
            }
        } else {
            console.error('invalid export type');
            return;
        }
    };
    this.derive = function (options) {
        // == Chequeo de errores
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for deriving ECDH keys.');
            return;
        }
        if (getCryptoKey(options.name) != -1) {
            console.error('key name "', options.name, '" already in use.');
            return;
        }
        if (!tools.isDefined(options.privateKeyName) || !tools.isDefined(options.publicKeyName)) {
            console.error('deriving keys require two previously stored keys.');
            return;
        }
        if (getKey(options.privateKeyName) == -1) {
            console.error('private key "', options.privateKeyName, '" not found.');
            return;
        }
        if (getKey(options.publicKeyName) == -1) {
            console.error('public key "', options.publicKeyName, '" not found.');
            return;
        }
        if (getKey(options.privateKeyName).type != 'mixed') {
            if (getKey(options.privateKeyName).type != 'private') {
                console.error('key "', options.privateKeyName, '" is not a valid private key.');
                return;
            }
            if (getKey(options.publicKeyName).type != 'public') {
                console.error('key "', options.publicKeyName, '" is not a valid public key.');
                return;
            }
        }
        // == Establecer defectos si no se han definido.            
        if (!tools.isDefined(options.targetClass)) {
            options.targetClass = 'AES-GCM';
        }
        if (!tools.isDefined(options.targetLength)) {
            options.targetLength = 256;
        }
        if (!tools.isDefined(options.namedCurve)) {
            options.namedCurve = 'P-256';
        }
        if (!tools.isDefined(options.exportable)) {
            options.exportable = false;
        }
        //console.log('public', getKey(options.publicKeyName).key);
        // == Derivacion
        var promise = new Promise(function (resolve, reject) {
            crypto.subtle.deriveKey({
                name: 'ECDH',
                namedCurve: options.namedCurve,
                public: getKey(options.publicKeyName).key.publicKey
            }, getKey(options.privateKeyName).key.privateKey, {
                name: options.targetClass,
                length: options.targetLength
            }, options.exportable, ['encrypt', 'decrypt']).then(function (key) {
                key = { publicKey: key };
                if (options.exportable) {
                    var gRaw, gJwk;
                    crypto.subtle.exportKey('jwk', key.publicKey).then(function (eJwk) {
                        gJwk = eJwk;
                        crypto.subtle.exportKey('raw', key.publicKey).then(function (eRaw) {
                            gRaw = eRaw;
                            cryptoKeys.push({
                                class: options.targetClass,
                                type: 'private',
                                name: options.name,
                                key: key,
                                jwk: gJwk,
                                raw: gRaw
                            });
                            if (getCryptoKey(options.name) != -1) {
                                if (!tools.isDefined(defaultCryptoKey)) defaultCryptoKey = options.name;
                                resolve(options.name);
                            } else {
                                reject('key was not added to storage.');
                            }
                        });
                    }).catch(function (err) {
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
            }).catch(function (err) {
                console.log('error deriving key: ', err, '.');
                reject(err);
            });
        });
        promise.success = function (fn) {
            promise.then(function (name) {
                fn(name);
            });
            return promise;
        };
        promise.error = function (fn) {
            promise.then(null, function (name) {
                fn(name);
            });
            return promise;
        };
        return promise;
    };
    this.encrypt = function (options) {
        if (tools.isDefined(options.default)) {
            if (options.default) if (tools.isDefined(defaultCryptoKey)) {
                options.name = defaultCryptoKey;
            } else {
                console.error('default key is not defined.');
                return;
            }
        }
        // == Verificacion de errores
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for deriving ECDH keys.');
            return;
        }
        if (!tools.isDefined(options.data)) {
            console.error('data option must be defined and not null.');
            return;
        }
        // == Obtener llave
        if (getCryptoKey(options.name) == -1) {
            console.error('Key "', options.name, '" not found.');
            return;
        }
        // == Validar capacidad de la llave
        if (getCryptoKey(options.name).class == 'ECDH') {
            console.error('Key "', options.name, '" is not valid for encryption.');
            return;
        }
        // == Defectos
        if (!tools.isDefined(options.tagLength)) {
            options.tagLength = 128;
        }
        // == IV (vector de inicializacion)
        var encIV = crypto.getRandomValues(new Uint8Array(12));
        // == Promesa
        var promise = new Promise(function (resolve, reject) {
            // == Cifrar
            crypto.subtle.encrypt({
                name: getCryptoKey(options.name).class,
                iv: encIV,
                tagLength: options.tagLength
            }, getCryptoKey(options.name).key.publicKey, tools.StringtoAB(options.data)).then(function (encrypted) {
                var data = {
                    encrypted: tools.ABToHS(new Uint8Array(encrypted)),
                    iv: tools.ABToHS(encIV)
                };
                // == Ejecutar promesa
                resolve(data);
            });
        });
        promise.success = function (fn) {
            promise.then(function (data) {
                fn(data.encrypted, data.iv);
            });
            return promise;
        };
        promise.error = function (fn) {
            promise.then(null, function (name) {
                fn(name);
            });
            return promise;
        };
        return promise;
    };
    this.decrypt = function (options) {
        if (tools.isDefined(options.default)) {
            if (options.default) if (tools.isDefined(defaultCryptoKey)) {
                options.name = defaultCryptoKey;
            } else {
                console.error('default key is not defined.');
                return;
            }
        }
        // == Comprobacion
        if (!tools.isDefined(options.name)) {
            console.error('key name is required for decrypting.');
            return;
        }
        if (!tools.isDefined(options.iv)) {
            console.error('the iv is required for decrypting.');
            return;
        }
        if (!tools.isDefined(options.data)) {
            console.error('data option must be defined and not null.');
            return;
        }
        // == Obtener llave
        if (getCryptoKey(options.name) == -1) {
            console.error('Key "', options.name, '" not found.');
            return;
        }
        // == Validar capacidad de la llave
        if (getCryptoKey(options.name).class == 'ECDH') {
            console.error('Key "', options.name, '" is not valid for encryption.');
            return;
        }
        // == Defectos
        if (!tools.isDefined(options.tagLength)) {
            options.tagLength = 128;
        }
        var promise = new Promise(function (resolve, reject) {
            crypto.subtle.decrypt({
                name: getCryptoKey(options.name).class,
                iv: tools.HSToAB(options.iv),
                tagLength: options.tagLength
            }, getCryptoKey(options.name).key.publicKey, tools.HSToAB(options.data)).then(function (dec) {
                data = {
                    decrypted: tools.ABtoString(new Uint8Array(dec))
                };
                resolve(data);
            }).catch(function (err) {
                reject(err);
            });
        });
        promise.success = function (fn) {
            promise.then(function (data) {
                fn(data.decrypted);
            });
            return promise;
        };
        promise.error = function (fn) {
            promise.then(null, function (name) {
                fn(name);
            });
            return promise;
        };
        return promise;
    };
    // == Servicio
    this.$get = function () {
        var $webCryptoProvider = _this;
        return {
            tools: {
                ArrayBufferToHexString: function ArrayBufferToHexString(ab) {
                    return tools.ABToHS(ab);
                },
                HexStringToArrayBuffer: function HexStringToArrayBuffer(hs) {
                    return tools.HSToAB(hs);
                },
                ArrayBufferToString: function ArrayBufferToString(ab) {
                    return tools.ABtoString(ab);
                },
                StringToArrayBuffer: function StringToArrayBuffer(str) {
                    return tools.StringtoAB(str);
                }
            },
            import: function _import(raw) {
                var newName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                return $webCryptoProvider.importKey({
                    name: newName,
                    raw: raw
                });
            },
            importAndDeriveWithDefaultKey: function importAndDeriveWithDefaultKey(raw) {
                var defKeys = $webCryptoProvider.getDefaultKeys();
                var importName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                var rsaKeyName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                if (tools.isDefined(defKeys.ecdh)) {
                    var promise = new Promise(function (resolve, reject) {
                        $webCryptoProvider.importKey({
                            name: importName,
                            raw: raw
                        }).success(function (importedKeyName) {
                            $webCryptoProvider.derive({
                                name: rsaKeyName,
                                privateKeyName: defKeys.ecdh,
                                publicKeyName: importedKeyName
                            }).success(function (derivedKeyName) {
                                resolve(derivedKeyName);
                            });
                        });
                    });
                    promise.success = function (fn) {
                        promise.then(function (data) {
                            fn(data);
                        });
                        return promise;
                    };
                    promise.error = function (fn) {
                        promise.then(null, function (name) {
                            fn(name);
                        });
                        return promise;
                    };
                    return promise;
                } else {
                    console.error('No default ECDH key defined.');
                }
            },
            importAndDerive: function importAndDerive(name, raw) {
                var importName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                var rsaKeyName = tools.ABToHS(crypto.getRandomValues(new Uint8Array(12)));
                var promise = new Promise(function (resolve, reject) {
                    $webCryptoProvider.importKey({
                        name: importName,
                        raw: raw
                    }).success(function (importedKeyName) {
                        $webCryptoProvider.derive({
                            name: rsaKeyName,
                            privateKeyName: name,
                            publicKeyName: importedKeyName
                        }).success(function (derivedKeyName) {
                            resolve(derivedKeyName);
                        });
                    });
                });
                promise.success = function (fn) {
                    promise.then(function (data) {
                        fn(data);
                    });
                    return promise;
                };
                promise.error = function (fn) {
                    promise.then(null, function (name) {
                        fn(name);
                    });
                    return promise;
                };
                return promise;
            },
            export: function _export(name) {
                return $webCryptoProvider.exportKey({ name: name });
            },
            exportDefaultKey: function exportDefaultKey() {
                return $webCryptoProvider.exportKey({ default: true });
            },
            encrypt: function encrypt(name, data) {
                return $webCryptoProvider.encrypt({ name: name, data: data });
            },
            decrypt: function decrypt(name, data, iv) {
                return $webCryptoProvider.decrypt({ name: name, data: data, iv: iv });
            },
            encryptWithDefaultKey: function encryptWithDefaultKey(data) {
                return $webCryptoProvider.encrypt({ default: true, data: data });
            },
            decryptWithDefaultKey: function decryptWithDefaultKey(data, iv) {
                return $webCryptoProvider.decrypt({ default: true, data: data, iv: iv });
            }
        };
    };
}).factory('$httpCrypto', function ($webCryptoProvider, $webCrypto, $http, $injector) {
    //This service is a WIP part, not tested but should be functional, requires a compatible
    //server.
    var tools = $injector.instantiate(NgWebCryptoUtils);
    return {
        post: function post(server, data) {
            var key = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;

            if (!tools.isDefined(server)) {
                console.error('please define "server" in the options.');
                return;
            }
            if (!tools.isDefined(data)) {
                data = {};
            }
            if (!tools.isDefined(key)) {
                key = $webCryptoProvider.getDefaultKeys().crypto;
                if (!tools.isDefined(key)) {
                    console.error('default crypto key is not defined');
                    return;
                }
            }
            if (!$webCryptoProvider.checkCryptoKey(key)) {
                console.error('key "', key, '" not found.');
                return;
            }
            var ucdata_str = JSON.stringify(data);
            var promise = new Promise(function (resolve, reject) {
                $webCryptoProvider.encrypt({
                    name: key,
                    data: ucdata_str
                }).success(function (encrypted, iv) {
                    var encData = {
                        data: encrypted,
                        iv: iv
                    };
                    $http.post(server, {
                        d: encrypted + '.' + iv
                    }).success(function (rdata, status, headers, config, statusText) {
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
                        $webCryptoProvider.decrypt({
                            name: key,
                            data: rdatao,
                            iv: rivo
                        }).success(function (decrypted) {
                            try {
                                var parsed = JSON.parse(decrypted);
                            } catch (e) {
                                console.error('decrypted response is not json.');
                                reject(decrypted);
                                return;
                            }
                            resultObj = {
                                data: parsed,
                                status: status,
                                headers: headers,
                                config: config,
                                statusText: statusText,
                                encrypted: encData
                            };
                            resolve(resultObj);
                        }).error(function (err) {
                            resultObj = {
                                data: null,
                                status: status,
                                headers: headers,
                                config: config,
                                statusText: statusText,
                                encrypted: encData
                            };
                            reject(resultObj);
                        });
                    }).error(function (rdata, status, headers, config, statusText) {
                        resultObj = {
                            data: null,
                            status: status,
                            headers: headers,
                            config: config,
                            statusText: statusText,
                            encrypted: encData
                        };
                        reject(resultObj);
                    });
                }).error(function (err) {
                    resultObj = {
                        data: null,
                        status: null,
                        headers: null,
                        config: config,
                        statusText: null,
                        encrypted: null
                    };
                    reject(resultObj);
                });
            });
            promise.success = function (fn) {
                promise.then(function (p) {
                    fn(p.data);
                });
                return promise;
            };
            promise.error = function (fn) {
                promise.then(null, function (name) {
                    fn(name);
                });
                return promise;
            };
            return promise;
        }
    };
});