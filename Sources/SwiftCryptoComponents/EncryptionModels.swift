//
//  EncryptionModels
//  
//
//  Created by Pape, Phillip on 1/25/19.
//  
//

import Foundation
import Security

public typealias PublicKey = SecKey
public typealias PrivateKey = SecKey
public typealias KeyPair = (PublicKey?, PrivateKey?) // 0 = public, 1 = private
public typealias SharedSecret = Data
public typealias Plaintext = Data
public typealias Ciphertext = Data

public struct ECKeyCoordinates {
    public let x: Data
    public let y: Data
}
