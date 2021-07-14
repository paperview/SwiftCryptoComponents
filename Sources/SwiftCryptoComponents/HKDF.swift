//
//  HKDF.swift
//  
//
//  Created by Pape, Phillip on 1/25/19.
//  
//

import CommonCrypto
import Foundation

public class HKDF {
    // hkdf following this spec https://tools.ietf.org/html/rfc5869#ref-HKDF-paper
    // tested with test vectors therein

    public init() {
        
    }

    public func hkdf(ikm: NSData, salt: NSData, info: NSData?, outputLength: Int) -> NSData {

        let algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)

        // Step 1: Extract

        // PRK = HMAC-Hash(salt, IKM)
        let prk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))

        CCHmac(algorithm, salt.bytes, salt.length, ikm.bytes, ikm.length, prk)

        // Step 2: Expand

        // N = ceil(L/HashLen)
        let n = Int(ceil(Double(outputLength) / Double(CC_SHA256_DIGEST_LENGTH)))

        // T(0) = empty string (zero length)
        var tOfN = NSData()

        // OKM output keying material (of L octets)
        let okm = NSMutableData()

        // T(0) = empty string (zero length)
        // T(N) = HMAC-Hash(PRK, T(N - 1) | info | 0x01)
        for i in 0 ..< n {
            var ctx = CCHmacContext()
            CCHmacInit(&ctx, algorithm, prk, Int(CC_SHA256_DIGEST_LENGTH))
            CCHmacUpdate(&ctx, tOfN.bytes, tOfN.length)
            if let infoUnwrapped = info {
                CCHmacUpdate(&ctx, infoUnwrapped.bytes, infoUnwrapped.length)
            }

            var c = UInt8(i + 1)
            CCHmacUpdate(&ctx, &c, 1)

            let bitsOfT = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
            bitsOfT.initialize(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CCHmacFinal(&ctx, bitsOfT)
            let stepResult = NSData(bytes: bitsOfT, length: Int(CC_SHA256_DIGEST_LENGTH))

            okm.append(stepResult as Data)
            tOfN = stepResult.copy() as! NSData
        }

        // OKM = first L octets of T
        return NSData(bytes: okm.bytes, length: outputLength)
    }
}
