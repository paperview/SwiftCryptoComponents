//
//  EncryptedPayload.swift
//  
//
//  Created by Pape, Phillip on 8/2/19.
//  
//

import Foundation

public struct JWEEncryptedPayload {
    public let jweString: String
    
    public init(plaintextPayload: Data,
                algorithm: JWEEncryptionAlgorithm,
                encryptionKey: EncryptionKey) throws {
        let jwe = try JWEObject(encryptionKey: encryptionKey,
                                encryptionAlgorithm: algorithm,
                                plaintext: plaintextPayload)
        self.jweString = jwe.string
    }
}

public struct JWEDecryptedPayload {
    public let plaintextPayload: DecryptedPayload

    public init(jweString: String,
                algorithm: JWEEncryptionAlgorithm,
                encryptionKey: EncryptionKey) throws {
        switch algorithm {
        case .direct:
            plaintextPayload = try JWEDirectEncrypter().decrypt(jweString: jweString, withKey: encryptionKey)
        case .keyWrap:
            plaintextPayload = try JWEKeyWrapEncrypter().decrypt(jweString: jweString, withKey: encryptionKey)
        }
    }
}
