//
//  SecureTransformer.swift
//  iOSOwaspSec
//
//  Created by Felipe Menezes on 23/09/24.
//

import Foundation
import CryptoKit

@objc(SecureTransformer)
class SecureTransformer: ValueTransformer {
    static var key: SymmetricKey = {
           // Retrieve the key from the Keychain or generate a new one
        if let storedKeyData = KeychainHelper
            .retrieveKey(alias: KeychainHelper.keyAlias) {
               return SymmetricKey(data: storedKeyData)
           } else {
               let newKey = SymmetricKey(size: .bits256)
               let keyData = newKey.withUnsafeBytes { Data($0) }
               KeychainHelper.storeKey(keyData,
                                       alias: KeychainHelper.keyAlias)
               return newKey
           }
       }()

    override class func transformedValueClass() -> AnyClass {
        return NSData.self
    }

    override func transformedValue(_ value: Any?) -> Any? {
        guard let stringValue = value as? String else { return nil }
        let data = Data(stringValue.utf8)
        guard let sealedBox = try? ChaChaPoly.seal(data, using: SecureTransformer.key) else { return nil }
        return sealedBox.combined as NSData
    }

    override func reverseTransformedValue(_ value: Any?) -> Any? {
        guard let data = value as? Data else { return nil }
        guard let sealedBox = try? ChaChaPoly.SealedBox(combined: data),
              let decryptedData = try? ChaChaPoly.open(sealedBox, using: SecureTransformer.key) else { return nil }
        return String(data: decryptedData, encoding: .utf8)
    }
}

import Security

class KeychainHelper {
    static let keyAlias = "com.fmmobile.personalvault.privatekey.data"
    static func storeKey(_ keyData: Data, alias: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: alias.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete any existing key
        SecItemDelete(query as CFDictionary)

        // Add new key
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            print("Error storing key: \(status)")
        }
    }

    static func retrieveKey(alias: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: alias.data(using: .utf8)!,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        if status == errSecSuccess, let keyData = dataTypeRef as? Data {
            return keyData
        } else {
            print("Error retrieving key: \(status)")
            return nil
        }
    }
}
