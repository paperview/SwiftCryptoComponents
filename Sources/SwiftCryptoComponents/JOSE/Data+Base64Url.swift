//
//  Data+Base64Url.swift
//  
//
//  Created by Pape, Phillip on 7/9/19.
//  
//

import Foundation

public typealias Base64UrlData = Data

extension Base64UrlData {
    
    public func toBase64UrlString() -> String {
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
