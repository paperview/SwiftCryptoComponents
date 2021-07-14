//
//  ECDSASignatureVerifier.swift
//  
//
//  Created by Pape, Phillip on 6/18/19.
//  
//

import Foundation

public enum ECDSASignatureVerificationError: Error {
    case jwsMalformed, invalidSignature, invalidHeaderOrClaimset, signatureVerifiationFailed, missingKey
}

internal class ECDSASignatureVerifier {

    func ecdsaVerifyJWS(jwsString pop: String, usingECKey ecKey: SecKey) throws -> Bool {
        guard let jwsComponents = JWSParser().getComponents(fromJWSPayload: pop) else {
            throw ECDSASignatureVerificationError.jwsMalformed
        }

        guard let signatureData = (jwsComponents.signature as Base64UrlString).toData(),
            let derSignatureData = DERTranscoder().derRepresentationForJWSSignature(signatureData: signatureData) else {
            throw ECDSASignatureVerificationError.invalidSignature
        }
        
        let digestString = jwsComponents.header + "." + jwsComponents.claimset
        guard let digestData = digestString.data(using: .utf8) else {
            throw ECDSASignatureVerificationError.invalidHeaderOrClaimset
        }
        
        let signature = derSignatureData as NSData
        let digestToVerify = HashFunction.sha256.digestFor(digestData) as NSData
        
        let result = ECKeySignatureManager().verify(signature: signature as CFData,
                                                    digest: digestToVerify as CFData,
                                                    publicKey: ecKey,
                                                    algorithm: SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256)
        
        if !result {
            throw ECDSASignatureVerificationError.signatureVerifiationFailed
        }

        return result
    }
    
}
