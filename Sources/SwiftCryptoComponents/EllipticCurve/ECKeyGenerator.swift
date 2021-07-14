//
//  ECKeyGenerator.swift
//  
//
//  Created by Pape, Phillip on 1/25/19.
//  
//

import Foundation
import Security

public enum ECKeyError: Error {
    case notAPublicEcKey
    case notAnECKey
}

public class ECKeyGenerator {

    public init() {

    }

    public func generateEllipticCurveKeyPair() -> KeyPair? {
        var keys: KeyPair? = (nil, nil)

        let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: 256,
                                         kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                         kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
        var error: Unmanaged<CFError>?

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }
        let publicKey = SecKeyCopyPublicKey(privateKey)
        keys?.0 = publicKey
        keys?.1 = privateKey
        return keys
    }
    
    public func getCoordinatesForECPublicKey(publicKey: SecKey) throws -> ECKeyCoordinates {

        var error: Unmanaged<CFError>?
        
        guard let keyCFData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw ECKeyError.notAPublicEcKey
        }
        var keyData = (keyCFData as NSData) as Data
        guard keyData.hexEncodedString().hasPrefix("04") else {
            throw ECKeyError.notAnECKey
        }
        
        keyData.remove(at: 0)
        let coordLength = (keyData as NSData).length / 2
        let x = keyData.prefix(upTo: coordLength)
        let y = keyData.suffix(from: coordLength)

        guard (x as NSData).length == (y as NSData).length else {
            throw ECKeyError.notAnECKey
        }
        
        return ECKeyCoordinates(x: x, y: y)
    }
    
    public func publicECKeyForJWK(jwkData data: Data) -> PublicKey? {
        guard let jwk = JWKReader().jwkObjectFromJSONData(data: data),
            let xData = Data(base64Encoded: (jwk.x as Base64UrlString).toBase64()),
            let yData = Data(base64Encoded: (jwk.y as Base64UrlString).toBase64()) else {
            return nil
        }

        return createPublicKeyFromCoordinates(ecKeyCoordinates: ECKeyCoordinates(x: xData, y: yData))
    }
    
    public func createPublicKeyFromCoordinates(ecKeyCoordinates: ECKeyCoordinates) -> PublicKey? {
        
        // For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y.
        let derHex = "04\(ecKeyCoordinates.x.hexEncodedString())\(ecKeyCoordinates.y.hexEncodedString())"
        let derb64 = derHex.base64EncodedHexadecimalString()
        guard let keyData = Data(base64Encoded: derb64) else {
            return nil
        }
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(keyData as NSData,
                                       [kSecAttrKeyType: kSecAttrKeyTypeEC,
                                        kSecAttrKeyClass: kSecAttrKeyClassPublic] as NSDictionary,
                                       &error)
        
        return key
    }
}
