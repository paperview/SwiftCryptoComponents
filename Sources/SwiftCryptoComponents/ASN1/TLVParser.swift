//
//  TLVParser.swift
//  
//
//  Created by Pape, Phillip on 6/14/19.
//  
//

import Foundation
import UIKit

internal protocol TLVParser {
    associatedtype TLVData
    associatedtype TLVObject
    typealias RemainingTLVData = TLVData
    func parse(_ data: TLVData) throws -> (TLVObject, RemainingTLVData)
}

internal struct DERTLVTypeParser: TLVParser {
    typealias TLVData = Data
    typealias TLVObject = DERASN1TypeIdentifier
    
    func parse(_ data: Data) throws -> (DERASN1TypeIdentifier, Data) {
        var remainder = data
        guard let identifierOctet = remainder.popFirst() else {
            throw DERDecodingError.NoType
        }
        
        let type = DERASN1TypeIdentifier(rawValue: identifierOctet & typeIdentifierBitMask)
        return (type ?? .endOfContent, remainder)
    }
}

internal struct DERTLVLengthParser: TLVParser {
    typealias TLVData = Data
    typealias TLVObject = DERTLVLength
    
    func parse(_ data: Data) throws -> (DERTLVLength, Data) {
        guard let (length, remainder) = DERTLVLengthProcessor().getContentLengthAndRemainder(fromLVData: data) else {
            throw DERDecodingError.NoLength
        }
        return (length, remainder)
    }
}

internal struct DERTLVValueParser: TLVParser {
    typealias TLVData = Data
    typealias TLVObject = DERTLVValue
    
    let valueLength: DERTLVLength
    
    init(length: DERTLVLength) {
        valueLength = length
    }
    
    func parse(_ data: Data) throws -> (DERTLVValue, Data) {
        guard valueLength <= data.count else {
            throw DERDecodingError.InvalidLength
        }
        let (value, remainder) = try DERTLVValueProcessor().extractValue(ofLength: valueLength, fromData: data)
        return (value, remainder)
    }
}
