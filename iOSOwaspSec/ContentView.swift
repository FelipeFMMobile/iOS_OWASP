//
//  ContentView.swift
//  iOSOwaspSec
//
//  Created by Felipe Menezes on 18/09/24.
//

import SwiftUI
import CoreData

struct ContentView: View {
    @Environment(\.managedObjectContext) private var viewContext

    @FetchRequest(
        sortDescriptors: [NSSortDescriptor(keyPath: \Item.timestamp, ascending: true)],
        animation: .default)
    private var items: FetchedResults<Item>
    @FetchRequest(
        sortDescriptors: [],
        animation: .default)
    private var users: FetchedResults<User>
    @State private var userName = ""
    @State private var passWord = ""
    @State private var address = ""
    @State private var pdfURLString = "https://conasems-ava-prod.s3.sa-east-1.amazonaws.com/aulas/ava/dummy-1641923583.pdf"
    @State private var alertPassCode = false
    @State private var alertPublicKey = false
    @State private var privateKey = ""
    @State private var decryptedText = ""
    private var vault = PersonalVault()

    var body: some View {
        NavigationView {
            Form {
                Section("Your name") {
                    TextField("Type you name here", text: $userName)
                        .keyboardType(.namePhonePad)
                        .submitLabel(.send)
                        .onSubmit {
                            Task {
                                if await vault
                                    .saveUsernameToKeychain(username: userName) {
                                    let user = await vault.getUsernameFromKeychain() ?? ""
                                    print("userName saved: \(user) in KeinChain")
                                }
                            }
                        }.onAppear {
                            Task {
                                userName = await vault.getUsernameFromKeychain() ?? ""
                            }
                        }
                        
                }
                Section("Password") {
                    SecureField("Type you password", text: $passWord)
                        .keyboardType(.default)
                        .textContentType(.newPassword)
                        .submitLabel(.send)
                        .onSubmit {
                            Task {
                                if await checkDeviceSecurity() {
                                    if await vault
                                        .savePassword(password: passWord) {
                                        let pass = await vault.retrieveKeychainPassword() ?? ""
                                        print("password saved: \(pass) in KeinChain")
                                    }
                                }
                            }
                        }
                        .onAppear {
                            Task {
                                passWord = await vault.retrieveKeychainPassword() ?? ""
                            }
                        }
                        .alert("Important",
                                isPresented: $alertPassCode) {
                            Text("Your device must set a passcode!")
                        }
                }
                Section("Pdf file url (file storage)") {
                    TextField("Insert pdf file url", text: $pdfURLString)
                        .keyboardType(.default)
                        .submitLabel(.send)
                        .onSubmit {
                            Task {
                                await vault.downloadAndSavePDF(url: URL(string: pdfURLString)!)
                            }
                        }
                }
                Section("Create a private key (only in device)") {
                    TextField("private key hash", text: $privateKey)
                        .keyboardType(.default)
                        .submitLabel(.join)
                        .onSubmit {
                            Task {
                                if let _ = await vault.generateSecureEnclavePrivateKey() {
                                    if let pKey = await vault.getSecureEnclavePrivateKey() {
                                        privateKey = pKey.hashValue.description
                                        if let encrypted = await vault.encryptMessage(message: userName) {
                                            self.decryptedText = await vault.decryptMessage(cipherText: encrypted,
                                                                                            privateKey: pKey) ?? ""
                                            alertPublicKey = true
                                        }
                                    }
                                }
                            }
                        }
                    if alertPublicKey {
                        Text("The data was encrypted with a public key pair from the private key secured in SecureEnclave!")
                        Text("Decrypted data: \(decryptedText)")
                    }
                }
                Section("User Address (coreData storage)") {
                    TextField("Type your address", text: $address)
                        .keyboardType(.namePhonePad)
                        .submitLabel(.send)
                        .onSubmit {
                            Task {
                                try? saveAddress()
                            }
                        }.onAppear {
                            Task {
                                await vault.verifyFileProtection()
                                try? getAddress()
                            }
                        }
                }
            }
            .toolbar {
                ToolbarItem {
                    Button(action: cleanData) {
                        Label("Clean Data", systemImage: "trash")
                    }
                }
            }.navigationTitle("Personal Information")
        }
    }

    private func saveAddress() throws {
        do {
            if let user = users.first {
                user.setValue(address, forKey: "address")
            } else {
                let user = User(context: viewContext)
                user.setValue(address, forKey: "address")
            }
            try viewContext.save()
        } catch {
            let nsError = error as NSError
            fatalError("Unresolved error \(nsError), \(nsError.userInfo)")
        }
    }

    private func getAddress() throws {
        if let user = users.first {
            if let encryptedData = user.value(forKey: "address") as? String {
                address = encryptedData
                print("Decrypted message: \(encryptedData)")
            }
        }
    }

    private func cleanData() {
        Task {
            await vault.cleanData()
            if let user = users.first {
                viewContext.delete(user)
                try viewContext.save()
            }
            alertPublicKey = false
        }
    }

    // MARK: functions

    private func checkDeviceSecurity() async -> Bool {
        if await vault.isPasscodeSet() {
            print("Passcode is set on the device.")
            return true
        } else {
            print("Passcode is not set on the device.")
            // Prompt the user to set a passcode or disable certain features
            alertPassCode.toggle()
            return false
        }
    }
}

private let itemFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .short
    formatter.timeStyle = .medium
    return formatter
}()

#Preview {
    ContentView().environment(\.managedObjectContext, PersistenceController.preview.container.viewContext)
}
