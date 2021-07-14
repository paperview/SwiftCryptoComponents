//
//  EncryptionExtensions.swift
//  
//
//  Created by Pape, Phillip on 1/25/19.
//  
//

import Foundation

extension FixedWidthInteger {
    func toBytes() -> [UInt8] {
        let result = [UInt8](withUnsafeBytes(of: self) { Data($0) })
        return result
    }
}

extension Data {
    private static let hexAlphabet = Array("0123456789abcdef".unicodeScalars)

    public func hexEncodedString() -> String {
        return String(self.reduce(into: "".unicodeScalars, { result, value in
            result.append(Data.hexAlphabet[Int(value / 16)])
            result.append(Data.hexAlphabet[Int(value % 16)])
        }))
    }

    public static func dataWithHexString(hex: String) -> Data {
        var data = Data()
        guard hex.count >= 2 else {
            return data
        }
        var hex = hex
        while hex.count > 0 {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let hexDigits = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var charInt32: UInt32 = 0
            Scanner(string: hexDigits).scanHexInt32(&charInt32)
            var charByte = UInt8(charInt32)
            data.append(&charByte, count: 1)
        }
        return data
    }
    
    public static func randomBytes(length: Int) -> Data {
        guard length > 0 else {
            return Data()
        }
        var data = Data(count: length)
        _ = data.withUnsafeMutableBytes {
            // If the data is not empty then the base address is not nil
            if let randomBytes = $0.baseAddress {
                _ = SecRandomCopyBytes(kSecRandomDefault, length, randomBytes)
            }
        }
        return data
    }
}

extension Data {
    
    public init<T>(from value: T) {
        var value = value
        self.init(buffer: UnsafeBufferPointer(start: &value, count: 1))
    }
    
    public func to<T>(type _: T.Type) -> T {
        //return withUnsafeBytes { $0.pointee } @phil see if this works when you can use new xcode
        return withUnsafeBytes { $0.load(as: T.self) }
    }
}

extension String {
    
    /// Creates `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    
    public var hexadecimal: Data? {
        guard let regex = try? NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive) else {
            return nil
        }
        
        var data = Data(capacity: count / 2)
        
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            guard let match = match else {
                return
            }
            
            let byteString = (self as NSString).substring(with: match.range)
            
            if let num = UInt8(byteString, radix: 16) {
                data.append(num)
            }
        }
        
        guard !data.isEmpty else {
            return nil
        }
        
        return data
    }
    
    /// Returns base64 encoded representation of a hexadecimal string
    public func base64EncodedHexadecimalString() -> String {
        return hexadecimal?.base64EncodedString() ?? ""
    }
    
    public func toBase64Encoded() -> String? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        return data.base64EncodedString()
    }
    
    public func fromBase64ToString() -> String? {
        var encoded64 = self
        
        if isStringBase64URL() {
            encoded64 = replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        }
        
        encoded64 = addPadding(to: encoded64)
        
        guard let data = Data(base64Encoded: encoded64, options: .ignoreUnknownCharacters) else {
            return nil
        }
        
        let decodedString = String(data: data, encoding: .utf8)
        
        return decodedString
    }
    
    private func addPadding(to base64: String) -> String {
        let remainder = base64.count % 4
        
        if remainder == 0 {
            return base64
        } else {
            let newLength = base64.count + (4 - remainder)
            return base64.padding(toLength: newLength, withPad: "=", startingAt: 0)
        }
    }
    
    private func isStringBase64URL() -> Bool {
        let base64URLSet = CharacterSet(charactersIn: "-_")
        return rangeOfCharacter(from: base64URLSet) != nil
    }
}

// MARK: - base64url: https://tools.ietf.org/html/rfc4648

extension String {
    public func base64url() -> String {
        guard let b64 = Data(base64Encoded: self),
            let b64Str = String(data: b64, encoding: .utf8) else {
                return ""
        }
        
        let base64url = b64Str
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64url
    }
}

extension Data {
    public func base64url() -> String {
        let b64 = base64EncodedData()
        guard let b64Str = String(data: b64, encoding: .utf8) else {
            return ""
        }
        
        let base64url = b64Str
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64url
    }
}
