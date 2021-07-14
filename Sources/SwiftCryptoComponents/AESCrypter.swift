//
//  AESCrypter.swift
//  
//
//  Created by Pape, Phillip on 1/25/19.
//
//

import CommonCrypto
import Foundation

public enum AESKeySizeBits: Int {
    case aes128 = 128, aes256 = 256
}

public enum AESKeySizeBytes: Int {
    case aes128 = 16, aes256 = 32
}

// The 128 or 256 in "AES 128" or "AES 256" is the key size.  so this should be determined by the size of the key.  the block size in gcm is always 128.
public enum AESEncryptionFlavor: Int {
    case aesGCM128 = 0, aesGCM256 = 1
}

internal class AESCrypter {
    
    // AES GCM 256
    func encrypt(flavor: AESEncryptionFlavor,
                 plainText: Data,
                 keyData: Data,
                 iv: Data,
                 tag: Data,
                 aad: Data = Data()) -> (Data, Data)? {
        
        let aadBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: aad.count)
        aad.copyBytes(to: aadBytes, count: aad.count)
        
        let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: (plainText as NSData).length + (iv as NSData).length + (aad as NSData).length)
        
        let tagLength = (tag as NSData).length
        let tagPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: tagLength)

        let pt = UnsafeMutablePointer<UInt8>.allocate(capacity: plainText.count)
        plainText.copyBytes(to: pt, count: plainText.count)
        
        let kd = UnsafeMutablePointer<UInt8>.allocate(capacity: keyData.count)
        keyData.copyBytes(to: kd, count: keyData.count)
        
        let ivd = UnsafeMutablePointer<UInt8>.allocate(capacity: iv.count)
        iv.copyBytes(to: ivd, count: iv.count)

        // If not using openssl, you can use CryptoKit as of iOS 13
        gcm_encrypt(aesGCMFlavor(rawValue: UInt32(flavor.rawValue)),
                    pt,
                    Int32((plainText as NSData).length),
                    aadBytes,
                    Int32((aad as NSData).length),
                    kd,
                    ivd,
                    Int32((iv as NSData).length),
                    cipherText,
                    tagPtr)
        
        var derivedTag = Data()
        if tagLength > 0 {
            // this pointers mem is deallocated below with tagPtr.deallocate()
            derivedTag = Data(buffer: UnsafeMutableBufferPointer(start: tagPtr, count: tagLength))
        }
        
        // AES GCM uses CTR mode under the hood, which means it turns form a block cipher into a stream cipher
        // so, the plaintext and ciphertext are of the same arbitrary length, not counting the IV and AAD
        // nice explanation: https://crypto.stackexchange.com/questions/5333/difference-between-stream-cipher-and-block-cipher
        let cph = Data(bytes: cipherText, count: (plainText as NSData).length)
        
        aadBytes.deallocate()
        cipherText.deallocate()
        tagPtr.deallocate()
        pt.deallocate()
        kd.deallocate()
        ivd.deallocate()
        
        return (cph, derivedTag)
        
    }
    
    func decrypt(flavor: AESEncryptionFlavor,
                 cipherText: Data,
                 keyData: Data,
                 iv: Data,
                 tag: Data,
                 aad: Data = Data()) -> Data? {
        
        let aadBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: aad.count)
        aad.copyBytes(to: aadBytes, count: aad.count)
        
        let plainText = UnsafeMutablePointer<UInt8>.allocate(capacity: (cipherText as NSData).length + (iv as NSData).length + (aad as NSData).length)
        
        let tagLength = (tag as NSData).length
        var tagBytes = [UInt8](repeating: 0, count: tagLength)
        
        if tagLength > 0 {
            tag.copyBytes(to: &tagBytes, count: tagLength)
        }
        
        let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: cipherText.count)
        cipherText.copyBytes(to: ct, count: cipherText.count)
        
        let kd = UnsafeMutablePointer<UInt8>.allocate(capacity: keyData.count)
        keyData.copyBytes(to: kd, count: keyData.count)
        
        let ivd = UnsafeMutablePointer<UInt8>.allocate(capacity: iv.count)
        iv.copyBytes(to: ivd, count: iv.count)

        // If not using openssl, you can use CryptoKit as of iOS 13
        gcm_decrypt(aesGCMFlavor(rawValue: UInt32(flavor.rawValue)),
                    ct,
                    Int32((cipherText as NSData).length),
                    aadBytes,
                    Int32((aad as NSData).length),
                    &tagBytes,
                    kd,
                    ivd,
                    Int32((iv as NSData).length),
                    plainText)
        
        // AES GCM uses CTR mode under the hood, which means it turns form a block cipher into a stream cipher
        // so, the plaintext and ciphertext are of the same arbitrary length, not counting the IV and AAD
        // nice explanation: https://crypto.stackexchange.com/questions/5333/difference-between-stream-cipher-and-block-cipher
        let pt = Data(bytes: plainText, count: (cipherText as NSData).length)
        
        aadBytes.deallocate()
        plainText.deallocate()
        ct.deallocate()
        kd.deallocate()
        ivd.deallocate()
        
        return pt
    }

}
