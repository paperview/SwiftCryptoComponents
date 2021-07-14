//
//  JWE.swift
//  
//
//  Created by Pape, Phillip on 7/26/19.
//  
//

import Foundation
import CommonCrypto

public struct JWEObject {
    public let string: String
    
    public init(encryptionKey: EncryptionKey, encryptionAlgorithm: JWEEncryptionAlgorithm, plaintext: Data) throws {
        
        switch encryptionAlgorithm {
        case .direct:
            string = try JWEDirectEncrypter().encrypt(plaintext: plaintext, withKey: encryptionKey)
        case .keyWrap:
            string = try JWEKeyWrapEncrypter().encrypt(plaintext: plaintext, withKey: encryptionKey)
        }
    }
}
