//
//  PersonalVault.swift
//  iOSOwaspSec
//
//  Created by Felipe Menezes on 22/09/24.
//

import Foundation
import Security
import LocalAuthentication


actor PersonalVault {
    //private let account = "com.fmmobile.personalvault"
    let accessGroup = "group.com.fmmobile.personalvault"
    let userNameTag = "com.fmmobile.personalvault.username.tag"
        .data(using: .utf8)!
    let passwordTag = "com.fmmobile.personalvault.password.tag"
        .data(using: .utf8)!
    let privateKeyTag = "com.fmmobile.personalvault.privatekey.tag"
        .data(using: .utf8)!

    // MARK: Username Secure
    func saveUsernameToKeychain(username: String) -> Bool {
        guard let data = username.data(using: .utf8) else {
            return false
        }
        
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: userNameTag,
            kSecAttrAccessGroup as String: accessGroup
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: userNameTag,
            kSecValueData as String: data,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        return status == errSecSuccess
    }

    func getUsernameFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: userNameTag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccessGroup as String: accessGroup
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let data = item as? Data, let username = String(data: data, encoding: .utf8) {
            return username
        }
        return nil
    }
    
    // MARK: Secure Password
    func savePassword(password: String) -> Bool {
        guard let data = password.data(using: .utf8) else {
                return false
            }
       var error: Unmanaged<CFError>?
       guard let access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     .userPresence, &error) else {
           return false
       }
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: passwordTag,
            kSecAttrAccessControl as String: access
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: passwordTag,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        //let errorMessage = SecCopyErrorMessageString(status, nil)
        return status == errSecSuccess
    }

    func retrieveKeychainPassword() -> String? {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     .userPresence, &error) else {
           return nil
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: passwordTag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccessControl as String: access
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let data = item as? Data, let username = String(data: data, encoding: .utf8) {
            return username
        }
        return nil
    }

    // MARK: File Storage
    func saveFileDataStorage(fromUrl: URL) {
        let fileManager = FileManager.default
        do {
            let documentsUrl = try fileManager.url(for: .documentDirectory,
                                                   in: .userDomainMask,
                                                   appropriateFor: nil,
                                                   create: false)
            let destinationFileUrl = documentsUrl.appendingPathComponent("myFile.pdf")
            if fileManager.fileExists(atPath: destinationFileUrl.path) {
                try fileManager.removeItem(at: destinationFileUrl)
            }
            try fileManager.moveItem(at: fromUrl, to: destinationFileUrl)
            let attributes = [FileAttributeKey.protectionKey: FileProtectionType.complete]
            try fileManager.setAttributes(attributes, ofItemAtPath: destinationFileUrl.path)
            
            print("File saved successfully at \(destinationFileUrl.path)")
        } catch {
            print("File Error: \(error.localizedDescription)")
        }
    }

    // MARK: PrivateKey SecureEnclave
    func generateSecureEnclavePrivateKey() -> SecKey? {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        ) else {
            print("Access control error: \(error!.takeRetainedValue() as Error)")
            return nil
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: privateKeyTag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print("Key generation error: \(error!.takeRetainedValue() as Error)")
            return nil
        }
        return privateKey
    }

    func getSecureEnclavePrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: privateKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let key = item {
            return (key as! SecKey)
        } else {
            print("Key not found or error: \(status)")
            return nil
        }
    }

    // MARK: Generate PublicKey / Encrypt & Decrypt
    func retrievePublicKey(privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey)
    }

    func encryptMessage(message: String) -> Data? {
        let publicKey = retrievePublicKey(privateKey: getSecureEnclavePrivateKey()!)!
        let plainText = Data(message.utf8)
        
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey,
                                                         SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM,
                                                         plainText as CFData,
                                                         &error) else {
            print("Encryption error: \(String(describing: error))")
            return nil
        }
        
        return cipherText as Data
    }

    func decryptMessage(cipherText: Data, privateKey: SecKey) -> String? {
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey,
                                                            SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM,
                                                            cipherText as CFData,
                                                            &error) else {
            print("Decryption error: \(String(describing: error))")
            return nil
        }
        
        return String(data: decryptedData as Data, encoding: .utf8)
    }


    // Check if the CoreData container is secure
    func verifyFileProtection() {
        guard let storeURL = PersistenceController.shared
            .container.persistentStoreCoordinator.persistentStores.first?.url else { return }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: storeURL.path)
            if let protection = attributes[.protectionKey] as? FileProtectionType {
                print("CoreData file protection is set to: \(protection.rawValue)")
            }
        } catch {
            print("Error retrieving file attributes: \(error.localizedDescription)")
        }
    }

    func isPasscodeSet() -> Bool {
        let context = LAContext()
        var error: NSError?
        
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        
        if canEvaluate {
            // The device has a passcode set
            return true
        } else {
            if let laError = error as? LAError {
                switch laError.code {
                case .passcodeNotSet:
                    // The device does not have a passcode set
                    return false
                default:
                    // Other errors (e.g., biometrics not available)
                    print("Authentication error: \(laError.localizedDescription)")
                    return false
                }
            }
            // If error is not LAError, return false
            return false
        }
    }

    func cleanData() {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: passwordTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let privateQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: privateKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        SecItemDelete(privateQuery as CFDictionary)
        let userQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: userNameTag,
            kSecAttrAccessGroup as String: accessGroup
        ]
        SecItemDelete(userQuery as CFDictionary)
    }
    
}

extension PersonalVault {
    func downloadAndSavePDF(url: URL) {
        // Create a URLSession configuration with default settings
        let sessionConfig = URLSessionConfiguration.default
        let session = URLSession(configuration: sessionConfig)
        
        // Create a download task
        let downloadTask = session.downloadTask(with: url) { (tempLocalUrl, response, error) in
            if let error = error {
                print("Download Error: \(error.localizedDescription)")
                return
            }
            
            guard let tempLocalUrl = tempLocalUrl else {
                print("No file URL.")
                return
            }
            Task {
                await self.saveFileDataStorage(fromUrl: tempLocalUrl)
            }
        }
        // Start the download task
        downloadTask.resume()
    }
}
