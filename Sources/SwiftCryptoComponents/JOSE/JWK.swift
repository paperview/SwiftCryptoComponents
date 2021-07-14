//
//  JWK.swift
//  
//
//  Created by Pape, Phillip on 6/24/19.
//  
//

import Foundation

public struct ServiceProviderJSONWebKey: Codable {
    public let kty: String
    public let use: String
    public let crv: String
    public let kid: String
    public let x: String
    public let y: String
}

public class JWKReader {
    public init() {}
    public func jwkObjectFromJSONData(data: Data) -> ServiceProviderJSONWebKey? {
        guard let key = try? JSONDecoder().decode(ServiceProviderJSONWebKey.self, from: data) else {
            return nil
        }
        return key
    }
}
