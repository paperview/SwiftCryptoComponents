//
//  LengthValueBuffer.swift
//  
//
//  Created by Pape, Phillip on 6/26/19.
//  
//

import Foundation

internal struct LengthValueBuffer32BigEndian {
    
    let bytes: Data
    
    init(parameters: [Data]) {
        
        var dataBuffer = Data()
        
        for param in parameters {
            let paramSize = (param as NSData).length
            let paramBytes = (param as NSData).bytes

            let lengthValue = Data(Int32(paramSize).bigEndian.toBytes())
            let valueBytes = Data(bytes: paramBytes, count: paramSize)
            
            dataBuffer += (lengthValue + valueBytes)
        }
        
        bytes = dataBuffer

    }
}
