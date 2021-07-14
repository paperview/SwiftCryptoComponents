//
//  DERASN1Decoding.swift
//  
//
//  Created by Pape, Phillip on 7/2/19.
//  
//

import Foundation

internal let constructedBitMask: UInt8 = 0x20
internal let typeIdentifierBitMask: UInt8 = 0x1F
internal let multibyteLengthBitMask: UInt8 = 0x80

internal enum DERASN1TypeIdentifier: UInt8 {
    case endOfContent = 0x00
    case boolean = 0x01
    case integer = 0x02
    case bitString = 0x03
    case octetString = 0x04
    case null = 0x05
    case objectIdentifier = 0x06
    case objectDescriptor = 0x07
    case external = 0x08
    case read = 0x09
    case enumerated = 0x0A
    case embeddedPdv = 0x0B
    case utf8String = 0x0C
    case relativeOid = 0x0D
    case sequence = 0x10
    case set = 0x11
    case numericString = 0x12
    case printableString = 0x13
    case t61String = 0x14
    case videotexString = 0x15
    case ia5String = 0x16
    case utcTime = 0x17
    case generalizedTime = 0x18
    case graphicString = 0x19
    case visibleString = 0x1A
    case generalString = 0x1B
    case universalString = 0x1C
    case characterString = 0x1D
    case bmpString = 0x1E
}

internal enum DERASN1ObjectId: String {
    case none
    case unparsed
    case ecPublicKey = "1.2.840.10045.2.1"
    case prime256v1 = "1.2.840.10045.3.1.7"
}

internal enum DERASN1EncodingMethod {
    case primitive, constructed
}

internal enum DERDecodingError: Error {
    case NoType
    case NoLength
    case InvalidLength
    case NoValue
    case NoObject
}

internal struct DERTLVLengthProcessor {
    private func derASN1LengthOctetIntValue(fromData data: Data) -> UInt64? {        
        guard data.count <= 8 else { // check if the int value can fit in 64 bits
            return nil
        }
        
        var value: UInt64 = 0
        for (i, b) in data.enumerated() {
            // Big Endian, so on first iteration we want the shift left by 8 bits to happen (count - 1) many times.
            // The final and rightmost bit should be shifted by zero as its place holds.
            let v = UInt64(b) << UInt64(8 * ((data.count - 1) - i))
            value += v
        }
        return value
    }
    
    func getContentLengthAndRemainder(fromLVData data: Data) -> (UInt64, Data)? {
        var iterator = data.makeIterator()
        let lengthValueFirstByte = iterator.next()
        
        guard let firstOctet = lengthValueFirstByte else {
            return nil
        }
        
        // Remove data as it is processed for length
        var remainderData = data
        remainderData.removeFirst()
        
        // In X.690 specs DER, the first bit of the length byte denotes whether the length number itself is multibyte
        if (firstOctet & multibyteLengthBitMask) != 0 { // multibyte length number
            let octetsToRead = firstOctet - multibyteLengthBitMask // 0 - 127
            var lengthDigitData = Data()
            for _ in 0..<octetsToRead {
                if let n = iterator.next() {
                    lengthDigitData.append(n)
                    remainderData.removeFirst()
                }
            }
            return (derASN1LengthOctetIntValue(fromData: lengthDigitData) ?? 0, remainderData)
        } else { // single byte length number
            return (UInt64(firstOctet), remainderData)
        }
    }
}

internal struct DERTLVValueProcessor {
    func extractValue(ofLength length: DERTLVLength, fromData data: Data) throws -> (DERTLVValue, Data) {
        guard length <= data.count else {
            throw DERDecodingError.InvalidLength
        }
        var iterator = data.makeIterator()
        var remainderData = data
        var valueData = Data()
        for _ in 0..<length {
            if let n = iterator.next() {
                valueData.append(n)
                remainderData.removeFirst()
            }
        }
        return (valueData, remainderData)
    }
}
