//
//  JWS.swift
//  
//
//  Created by Pape, Phillip on 6/28/19.
//  
//

import Foundation

public struct JWSComponents {
    public let header: String
    public let claimset: String
    public let signature: String
}

public class JWSParser {
    
    public func getComponents(fromJWSPayload payload: String) -> JWSComponents? {
        let dotSeparatedComponents = payload.split(separator: ".")
        guard dotSeparatedComponents.count == 3 else {
            return nil
        }
        
        return JWSComponents(header: String(dotSeparatedComponents[0]),
                             claimset: String(dotSeparatedComponents[1]),
                             signature: String(dotSeparatedComponents[2]))
    }
}
