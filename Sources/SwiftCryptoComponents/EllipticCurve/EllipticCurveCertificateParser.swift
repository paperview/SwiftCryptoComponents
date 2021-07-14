//
//  EllipticCurveCertificateParser.swift
//  
//
//  Created by Pape, Phillip on 10/4/19.
//  
//

import Foundation
import CommonCrypto

enum CertificateParserError: Error {
    case invalidIdentity
}

/// This class can be used to parse .der and .p12 certificates
public class EllipticCurveCertificateParser {
    
    public init() {}
        
    internal func identity(data: Data, password: String) throws -> SecIdentity {
        var importResult: CFArray?
        let err = SecPKCS12Import(
            data as NSData,
            [kSecImportExportPassphrase as String: password] as NSDictionary,
            &importResult
        )
        guard err == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
        }
        guard let identityDictionaries = importResult as? [[String: Any]],
            let identity = identityDictionaries[0][kSecImportItemIdentity as String] else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
        }
        
        guard CFGetTypeID(identity as CFTypeRef) == SecIdentityGetTypeID() else {
            throw CertificateParserError.invalidIdentity
        }
        
        // this force unwrap cannot be avoided, but we check for the type in the gaurd above.
        // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/identities/importing_an_identity
        return identity as! SecIdentity
    }
    
    public func getPrivateKey(fromData p12Data: Data) -> PrivateKey? {
        guard let secIdentity = try? identity(data: p12Data, password: "qwerty") else {
            return nil
        }
        var privateKey: SecKey?
        let securityError = SecIdentityCopyPrivateKey(secIdentity, &privateKey)
        if securityError != noErr {
            privateKey = nil
        }
        return privateKey
    }
    
    public func getPublicKey(fromData derData: Data) -> PublicKey? {
        var publicKey: SecKey?
        guard let cert = SecCertificateCreateWithData(kCFAllocatorDefault, derData as CFData) else {
            return nil
        }
        var optionalTrust: SecTrust?
        let status = SecTrustCreateWithCertificates(cert, SecPolicyCreateBasicX509(), &optionalTrust)
        if status == errSecSuccess {
            guard let trust = optionalTrust else {
                return nil
            }
            let semaphore = DispatchSemaphore(value: 0)
            SecTrustEvaluateAsync(trust, DispatchQueue.global()) { _, trustResult in
                switch trustResult {
                case .proceed, .unspecified:
                    let pbk = SecTrustCopyPublicKey(trust)
                    publicKey = pbk
                    semaphore.signal()
                case .recoverableTrustFailure:
                    let pbk = SecTrustCopyPublicKey(trust)
                    publicKey = pbk
                    semaphore.signal()
                default:
                    semaphore.signal()
                }
            }
            semaphore.wait()
        }
        
        return publicKey
    }
}
