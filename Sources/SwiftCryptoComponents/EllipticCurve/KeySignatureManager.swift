//
//  ECKeySignatureManager.swift
//  
//
//  Created by Pape, Phillip on 1/25/19.
//  
//

import Foundation

internal class ECKeySignatureManager {

    func sign(digest: Data, privateKey: PrivateKey, algorithm: SecKeyAlgorithm) -> CFData? {
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            return nil
        }

        var error: Unmanaged<CFError>?
        
        let result = SecKeyCreateSignature(privateKey,
                                           algorithm,
                                           digest as NSData,
                                           &error)

        if let _ = error {
            return nil
        }
        
        return result

    }

    func verify(signature: CFData, digest: CFData, publicKey: PublicKey, algorithm: SecKeyAlgorithm) -> Bool {
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            return false
        }
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey,
                                           algorithm,
                                           digest,
                                           signature,
                                           &error)
        
        if let _ = error {
            return false
        }
        
        return result
    }
}

public class SymmetricKeySignatureManager {
    public init() {}
    public func verify(signature: Data, usingKey key: Data, withPayloadData payloadData: Data) -> Bool {
        let hmacSha256 = MACVerifier().performHmacSHA256(withMacKey: key, onMacData: payloadData)
        return signature == hmacSha256
    }
    
    public func getSignature(usingKey key: Data, withPayloadData payloadData: Data) -> Data {
        return MACVerifier().performHmacSHA256(withMacKey: key, onMacData: payloadData)
    }
}
