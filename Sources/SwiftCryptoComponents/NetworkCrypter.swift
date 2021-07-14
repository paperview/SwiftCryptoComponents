//
//  NetworkCrypter.swift
//  
//
//  Created by Pape, Phillip on 7/19/19.
//  
//

import Foundation
import CommonCrypto

public enum NetworkCrypterError: Error {
    case failedToEncryptData, failedToDecryptData, aesKeyNot128Or256BitLength
}

public struct AESEncryptionResult {
    public let ciphertext: Ciphertext
    public let derivedTag: Data
}

/// Encrypts and decrypts payloads and fields for  interaction
public class NetworkCrypter {
    
    public init() {}
    
    /// Encrypt data for  interaction given a particular key
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - key: key for encryption
    ///   - iv: iv
    ///   - tag: optional tag
    ///   - aad: optional aad
    /// - Returns: ciphertext data and the aead in an AESEncryptionResult
    /// - Throws: CrypterError if data could not be encrypted
    public func encryptAESGCM(data: Data, key: Data, iv: Data, tag: Data = Data(), aad: Data = Data()) throws -> AESEncryptionResult {
        
        let keySize = key.count
        guard keySize == AESKeySizeBytes.aes128.rawValue || keySize == AESKeySizeBytes.aes256.rawValue else {
            throw NetworkCrypterError.aesKeyNot128Or256BitLength
        }
        let flavor: AESEncryptionFlavor = keySize == AESKeySizeBytes.aes128.rawValue ? .aesGCM128 : .aesGCM256
        
        do {
            guard let (ciphertext, tag) = AESCrypter().encrypt(flavor: flavor,
                                                               plainText: data,
                                                               keyData: key,
                                                               iv: iv,
                                                               tag: tag,
                                                               aad: aad) else {
                throw NetworkCrypterError.failedToEncryptData
            }
            return AESEncryptionResult(ciphertext: ciphertext, derivedTag: tag)
        } catch {
            throw NetworkCrypterError.failedToEncryptData
        }
    }

    /// Decrypt data for  interaction given a particular key
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - key: key for decryption
    ///   - iv: iv
    ///   - tag: optional tag
    ///   - aad: optional aad
    /// - Returns: plaintext data
    /// - Throws: CrypterError if data could not be decrypted
    public func decryptAESGCM(data: Data, key: Data, iv: Data, tag: Data = Data(), aad: Data = Data()) throws -> Plaintext {
        
        let keySize = key.count
        guard keySize == AESKeySizeBytes.aes128.rawValue || keySize == AESKeySizeBytes.aes256.rawValue else {
            throw NetworkCrypterError.aesKeyNot128Or256BitLength
        }
        let flavor: AESEncryptionFlavor = keySize == AESKeySizeBytes.aes128.rawValue ? .aesGCM128 : .aesGCM256
        
        do {
            guard let plaintext = AESCrypter().decrypt(flavor: flavor,
                                                       cipherText: data,
                                                       keyData: key,
                                                       iv: iv,
                                                       tag: tag,
                                                       aad: aad) else {
                throw NetworkCrypterError.failedToDecryptData
            }
            return plaintext
        } catch {
            throw NetworkCrypterError.failedToDecryptData
        }
    }
}
