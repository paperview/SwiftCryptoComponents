//
//  EncryptionKey.swift
//  
//
//  Created by Pape, Phillip on 10/1/19.
//  
//

import Foundation

public enum KeyCreationError: Error {
    case invalidKeyLength
}

/// A symmetric encryption key used for encrypting and decrypting on the network
/// .data - the bytes of the key
/// .purpose - what the key is intended to be used for
/// .size - the size in bytes
public struct EncryptionKey {
    public let data: Data
    public let size: AESKeySizeBytes
    
    public init(keyMaterial: Data) throws {
        guard let keySize = AESKeySizeBytes(rawValue: keyMaterial.count) else {
            throw KeyCreationError.invalidKeyLength
        }
        self.data = keyMaterial
        self.size = keySize
    }
}
