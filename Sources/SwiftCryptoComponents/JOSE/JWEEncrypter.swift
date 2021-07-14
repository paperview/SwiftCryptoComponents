//
//  JWEEncrypter.swift
//  
//
//  Created by Pape, Phillip on 10/2/19.
//  
//

import Foundation

public typealias EncryptedJWEString = String
public typealias DecryptedPayload = [String: Any]

internal protocol JWEEncrypter {
    func encrypt(plaintext: Data, withKey encryptionKey: EncryptionKey) throws -> EncryptedJWEString
    func decrypt(jweString: String, withKey encryptionKey: EncryptionKey) throws -> DecryptedPayload
}

public enum JWEEncryptionAlgorithm: String {
    case direct, keyWrap // 128kw vs 256kw are determined by the key size of the key used to create the jwe
}

public enum JWEParsingError: Error {
    case malformedPayload, failedToSerializeAAD, failedToSerializeHeader, malformedHeader, failedToSerializePlaintextPayload
}

internal struct JWEDirectEncrypter: JWEEncrypter {
    
    func encrypt(plaintext: Data, withKey encryptionKey: EncryptionKey) throws -> EncryptedJWEString {
        let keyIV = Data.randomBytes(length: EncryptionConstants.AESIVByteLength)
        let ivString = keyIV.base64EncodedString().toBase64Url()
        let encryptionType = encryptionKey.size == AESKeySizeBytes.aes128 ? "A128GCM" : "A256GCM"
        let header = ["alg": "dir", "enc": encryptionType, "typ": "JOSE"]
        
        guard let aadData = try? JSONSerialization.data(withJSONObject: header, options: []) else {
            throw JWEParsingError.failedToSerializeAAD
        }
        let aadStringB64Url = aadData.toBase64UrlString()
        guard let aadEncodedData = aadStringB64Url.data(using: .utf8) else {
            throw JWEParsingError.failedToSerializeAAD
        }
        
        let cipherText = try NetworkCrypter().encryptAESGCM(data: plaintext,
                                                                key: encryptionKey.data,
                                                                iv: keyIV,
                                                                tag: Data(count: EncryptionConstants.AESTagByteLength),
                                                                aad: aadEncodedData)
        
        let cipherTextString = cipherText.ciphertext.toBase64UrlString()
        
        guard let headerData = try? JSONSerialization.data(withJSONObject: header, options: []) else {
            throw JWEParsingError.failedToSerializeHeader
        }
        
        let headerString = headerData.toBase64UrlString()
        
        return headerString + ".." + ivString + "." + cipherTextString + "." + cipherText.derivedTag.toBase64UrlString()
    }
    
    func decrypt(jweString: String, withKey encryptionKey: EncryptionKey) throws -> DecryptedPayload {
        let pieces = jweString.split(separator: ".")
        
        guard pieces.count >= 4 else {
            throw JWEParsingError.malformedPayload
        }
        
        guard let _ = Data(base64Encoded: (String(pieces[0]) as Base64UrlString).toBase64()),
            let ivData = Data(base64Encoded: (String(pieces[1]) as Base64UrlString).toBase64()),
            let cipherTextData = Data(base64Encoded: (String(pieces[2]) as Base64UrlString).toBase64()),
            let tagData = Data(base64Encoded: (String(pieces[3]) as Base64UrlString).toBase64()) else {
                throw JWEParsingError.malformedPayload
        }
        
        guard let aadEncodedData = (String(pieces[0]) as Base64UrlString).data(using: .utf8) else {
            throw JWEParsingError.malformedHeader
        }
        
        let authPlainText = try NetworkCrypter().decryptAESGCM(data: cipherTextData,
                                                                   key: encryptionKey.data,
                                                                   iv: ivData,
                                                                   tag: tagData,
                                                                   aad: aadEncodedData)
        
        guard let plainTextPayload = try? JSONSerialization.jsonObject(with: authPlainText, options: []) as? [String: Any] else {
            throw JWEParsingError.failedToSerializePlaintextPayload
        }
        
        return plainTextPayload
    }
}

internal struct JWEKeyWrapEncrypter: JWEEncrypter {
    
    func encrypt(plaintext: Data, withKey encryptionKey: EncryptionKey) throws -> EncryptedJWEString {
        let cek = Data.randomBytes(length: encryptionKey.size.rawValue)
        let keyIV = Data.randomBytes(length: EncryptionConstants.AESIVByteLength)
        
        let authCiphCEK = try NetworkCrypter().encryptAESGCM(data: cek,
                                                                 key: encryptionKey.data,
                                                                 iv: keyIV,
                                                                 tag: Data(count: EncryptionConstants.AESTagByteLength))
        let encryptedKey = authCiphCEK.ciphertext.base64EncodedString().toBase64Url()
        let ivString = keyIV.base64EncodedString().toBase64Url()
        let authTag = authCiphCEK.derivedTag.base64EncodedString().toBase64Url()
        let algorithmType = encryptionKey.size == AESKeySizeBytes.aes128 ? "A128GCMKW" : "A256GCMKW"
        let encryptionType = encryptionKey.size == AESKeySizeBytes.aes128 ? "A128GCM" : "A256GCM"
        let updatedHeader = ["alg": algorithmType, "enc": encryptionType, "typ": "JOSE", "iv": ivString, "tag": authTag]
        
        // AAD is the b64url encoded header
        guard let aadData = try? JSONSerialization.data(withJSONObject: updatedHeader, options: []) else {
            throw JWEParsingError.failedToSerializeAAD
        }
        
        let aadStringB64Url = aadData.toBase64UrlString()
        
        // in nimbus this is ASCII
        guard let aadEncodedData = aadStringB64Url.data(using: .ascii) else {
            throw JWEParsingError.failedToSerializeAAD
        }
        
        let newIV = Data.randomBytes(length: EncryptionConstants.AESIVByteLength)
        
        let authCipherText = try NetworkCrypter().encryptAESGCM(data: plaintext,
                                                                    key: cek,
                                                                    iv: newIV,
                                                                    tag: Data(count: EncryptionConstants.AESTagByteLength),
                                                                    aad: aadEncodedData)
        
        let encryptedKeyString = encryptedKey
        let newIVString = newIV.toBase64UrlString()
        let cipherTextString = authCipherText.ciphertext.toBase64UrlString()
        let tagString = authCipherText.derivedTag.toBase64UrlString()
        
        guard let headerData = try? JSONSerialization.data(withJSONObject: updatedHeader, options: []) else {
            throw JWEParsingError.failedToSerializeHeader
        }
        
        let headerString = headerData.toBase64UrlString()
        
        return headerString + "." + encryptedKeyString + "." + newIVString + "." + cipherTextString + "." + tagString
    }
    
    func decrypt(jweString: String, withKey encryptionKey: EncryptionKey) throws -> DecryptedPayload {
        let pieces = jweString.split(separator: ".")
        
        guard pieces.count >= 5 else {
            throw JWEParsingError.malformedPayload
        }
        
        guard let headerData = Data(base64Encoded: (String(pieces[0]) as Base64UrlString).toBase64()),
            let encryptedKeyData = Data(base64Encoded: (String(pieces[1]) as Base64UrlString).toBase64()),
            let ivData = Data(base64Encoded: (String(pieces[2]) as Base64UrlString).toBase64()),
            let cipherTextData = Data(base64Encoded: (String(pieces[3]) as Base64UrlString).toBase64()),
            let tagData = Data(base64Encoded: (String(pieces[4]) as Base64UrlString).toBase64()) else {
                throw JWEParsingError.malformedPayload
        }
        
        guard let headerJSON = try? JSONSerialization.jsonObject(with: headerData, options: []) as? [String: String],
            let keyIVString = headerJSON["iv"],
            let keyTagString = headerJSON["tag"],
            let keyIV = Data(base64Encoded: (keyIVString as Base64UrlString).toBase64()),
            let keyTag = Data(base64Encoded: (keyTagString as Base64UrlString).toBase64()) else {
                throw JWEParsingError.malformedHeader
        }
        
        guard let aadEncodedData = (String(pieces[0]) as Base64UrlString).data(using: .ascii) else {
            throw JWEParsingError.malformedHeader
        }
        
        let plaintextCEK = try NetworkCrypter().decryptAESGCM(data: encryptedKeyData,
                                                                  key: encryptionKey.data,
                                                                  iv: keyIV,
                                                                  tag: keyTag)
        
        let authPlainText = try NetworkCrypter().decryptAESGCM(data: cipherTextData,
                                                                   key: plaintextCEK,
                                                                   iv: ivData,
                                                                   tag: tagData,
                                                                   aad: aadEncodedData)
        
        guard let plainTextPayload = try? JSONSerialization.jsonObject(with: authPlainText, options: []) as? [String: Any] else {
            throw JWEParsingError.failedToSerializePlaintextPayload
        }
        
        return plainTextPayload
    }
}
