//
//  Base64Url.swift
//  
//
//  Created by Pape, Phillip on 6/28/19.
//  
//

import Foundation

//https://tools.ietf.org/html/rfc4648
//5.  Base 64 Encoding with URL and Filename Safe Alphabet

public typealias Base64UrlString = String
public typealias Base64String = String

extension Base64UrlString {
    public func toData() -> Data? {
        guard let b64Data = Data(base64Encoded: toBase64()) else {
                return nil
        }
        
        return b64Data
    }
    
    public func toBase64() -> String {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
}

extension Base64String {
    public func toBase64Url() -> String {
        return self
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }
}
