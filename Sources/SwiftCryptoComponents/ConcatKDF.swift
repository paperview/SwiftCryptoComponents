//
//  ConcatKDF.swift
//
//
//  Created by Pape, Phillip on 5/30/19.
//  
//

import Foundation
import CommonCrypto

internal class ConcatKDF {
    // Section 5.8.1: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
    func ckdf(hash: HashFunction, z: Data, otherInfo: Data, keyDataLength: Int) throws -> Data {
        
        let concatenatedData: Data = z + otherInfo
        
        let hashLength = hash.hashLen
        guard hashLength > 0 else {
            throw ConcatKDFError.improperInput
        }
        let modLen = keyDataLength % hashLength
        
        // reps =  keydatalen / hashlen 
        let reps = (keyDataLength / hashLength) + (modLen > 0 ? 1 : 0)
        
        // If reps > (2^32 −1), then return an error indicator without performing the remaining actions.
        guard reps <= 0xFFFFFFFF as UInt64 else {
            throw ConcatKDFError.improperInput
        }
        
        var derivedKeyingMaterial = Data()
        
        // For i = 1 to reps by 1, do the following:
        for i in 1 ..< reps {
            // Compute K(i) = H(counter || Z || OtherInfo).
            derivedKeyingMaterial += hash.digestFor(intToData(value: UInt32(i).bigEndian) + concatenatedData)
            
            // Increment counter (i) (modulo 232), treating it as an unsigned 32-bit integer. (intToData)
        }
        
        // Set DerivedKeyingMaterial = K(1) || K(2) || ... || K(reps-1) || K_Last.
        
        // let K_Last be set to K(reps) if (keydatalen / hashlen) is an integer (always will be in our case)
        derivedKeyingMaterial += hash.digestFor(intToData(value: UInt32(reps).bigEndian) + concatenatedData)

        return derivedKeyingMaterial
    }
    
    // MARK: - Helper methods    
    private func intToData<T>(value: T) -> Data where T: FixedWidthInteger {
        var int = value
        return Data(bytes: &int, count: MemoryLayout<T>.size)
    }
}

internal enum ConcatKDFError: Error {
    case improperInput
}
