//
//  DERTranscoder.swift
//  
//
//  Created by Pape, Phillip on 7/2/19.
//  
//

import Foundation

internal enum DERTranscodingError: Error {
    case notValidDER
}

internal class DERTranscoder {
    func parseDER(data: Data) throws -> DERObjectTree<DERTLVObject>? {
        do {
            let tree = try createDERObjectTree(data: data)
            return tree
        } catch {
            throw DERTranscodingError.notValidDER
        }
    }
    
    private func createDERObjectTree(data: Data) throws -> DERObjectTree<DERTLVObject> {
        let objectParser = DERTLVObjectParser()
        do {
            return try objectParser.generateTree(data)
        } catch {
            throw error
        }
    }
    
    func extractRandSValuesFromDERSignature(signatureData: Data) -> (Data, Data)? {
        do {
            let tree = try createDERObjectTree(data: signatureData)
            let integerValues = tree.valuesForTypeIdentifier(typeId: .integer)
            if integerValues.count >= 2 {
                return (integerValues[0], integerValues[1])
            }
        } catch {
            return nil
        }
        
        return nil
    }
    
    func jwsRepresentationForSignature(signatureData: Data) -> Data? {
        guard let rAndS = extractRandSValuesFromDERSignature(signatureData: signatureData) else {
            return nil
        }
        
        // check if there are padded zeroes, r and s themselves are always 32 bytes
        let r = (rAndS.0.first == 0x00 && rAndS.0.count != 32) ? rAndS.0.dropFirst() : rAndS.0
        let s = (rAndS.1.first == 0x00 && rAndS.1.count != 32) ? rAndS.1.dropFirst() : rAndS.1
        
        let jwsData = r + s
        
        return jwsData
    }
    
//  https://tools.ietf.org/html/rfc3279#section-2.2.3
//  0x30|(Length of remaining data)|0x02|(Length of r)|r|0x02|(Length of s)|s, DER format certs
    func derRepresentationForJWSSignature(signatureData: Data) -> Data? {
        
        let hexRep = signatureData.hexEncodedString()
        
        let midway = hexRep.count / 2
        
        let rHex = hexRep.prefix(upTo: hexRep.index(hexRep.startIndex, offsetBy: midway))
        let sHex = hexRep.suffix(from: hexRep.index(hexRep.startIndex, offsetBy: midway))
        
        let firstByteRHex = String(rHex.prefix(upTo: rHex.index(rHex.startIndex, offsetBy: 2)))
        let firstByteSHex = String(sHex.prefix(upTo: sHex.index(sHex.startIndex, offsetBy: 2)))
        
        guard let firstByteR = Data(base64Encoded: firstByteRHex.base64EncodedHexadecimalString()), let firstByteS = Data(base64Encoded: firstByteSHex.base64EncodedHexadecimalString()) else {
            return nil
        }
        
        let firstByteRValue: UInt8 = firstByteR.to(type: UInt8.self)
        let firstByteSValue: UInt8 = firstByteS.to(type: UInt8.self)
        
        let fullRHex = firstByteRValue > 127 ? "00\(rHex)" : "\(rHex)" // if first bit is filled, number requires padding
        let fullSHex = firstByteSValue > 127 ? "00\(sHex)" : "\(sHex)" // if first bit is filled, number requires padding
        
        guard let fullR = Data(base64Encoded: fullRHex.base64EncodedHexadecimalString()),
            let fullS = Data(base64Encoded: fullSHex.base64EncodedHexadecimalString()) else {
                return nil
        }
        
        let fullRCount = fullR.count
        let fullSCount = fullS.count
        
        guard let fullByte = (fullRCount + fullSCount + 4).toBytes().first,
            let rByte = fullRCount.toBytes().first,
            let sByte = fullSCount.toBytes().first else {
                return nil
        }
        
        let fullCount = Data([fullByte]).hexEncodedString()
        let rCount = Data([rByte]).hexEncodedString()
        let sCount = Data([sByte]).hexEncodedString()
        
        let fullHex = "30\(fullCount)02\(rCount)\(fullRHex)02\(sCount)\(fullSHex)"
        return Data(base64Encoded: fullHex.base64EncodedHexadecimalString())
    }
}
