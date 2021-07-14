//
//  HashFunction.swift
//  
//
//  Created by Pape, Phillip on 6/7/19.
//  
//

import Foundation
import CommonCrypto

public enum HashFunction {
    case sha256
    case sha384
    case sha512
    
    public var hashLen: Int {
        switch self {
        case .sha256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
    
    public func digestFor(_ data: Data) -> Data {
        var digestData: [UInt8]
        switch self {
        case .sha256:
            digestData = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        case .sha384:
            digestData = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        case .sha512:
            digestData = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        }
        _ = CC_SHA256(Array(data), UInt32(data.count), &digestData)
        return Data(digestData)
    }
}
