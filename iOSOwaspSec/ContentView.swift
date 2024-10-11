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
    @State private var privateKey = ""
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
                Section("Pdf file url") {
                    TextField("Insert pdf file url", text: $pdfURLString)
                        .keyboardType(.default)
                        .submitLabel(.send)
                        .onSubmit {
                            Task {
                                await vault.downloadAndSavePDF(url: URL(string: pdfURLString)!)
                            }
                        }
                }
                Section("Create a private key") {
                    TextField("private key", text: $privateKey)
                        .keyboardType(.default)
                        .submitLabel(.join)
                        .onSubmit {
                            Task {
                                if let _ = await vault.generateSecureEnclavePrivateKey() {
                                    if let pKey = await vault.getSecureEnclavePrivateKey() {
                                        privateKey = getStringFromSecKey(pKey) ?? ""
                                    }
                                }
                            }
                        }
                }
                Section("User Address") {
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
                Section {
                    List {
                        ForEach(items) { item in
                            NavigationLink {
                                Text("Item at \(item.timestamp!, formatter: itemFormatter)")
                            } label: {
                                Text(item.timestamp!, formatter: itemFormatter)
                            }
                        }
                        .onDelete(perform: deleteItems)
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    EditButton()
                }
                ToolbarItem {
                    Button(action: addItem) {
                        Label("Add Item", systemImage: "plus")
                    }
                }
            }.navigationTitle("Personal Information")
        }
    }

    private func saveAddress() throws {
        do {
            if let user = users.first {
                user.setValue(address, forKey: "address")
                try user.managedObjectContext?.save()
            } else {
                let user = User(context: viewContext)
                user.setValue(address, forKey: "address")
                try user.managedObjectContext?.save()
            }
           
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

    private func addItem() {
        withAnimation {
            let newItem = Item(context: viewContext)
            newItem.timestamp = Date()

            do {
                try viewContext.save()
            } catch {
                // Replace this implementation with code to handle the error appropriately.
                // fatalError() causes the application to generate a crash log and terminate. You should not use this function in a shipping application, although it may be useful during development.
                let nsError = error as NSError
                fatalError("Unresolved error \(nsError), \(nsError.userInfo)")
            }
        }
    }

    private func deleteItems(offsets: IndexSet) {
        withAnimation {
            offsets.map { items[$0] }.forEach(viewContext.delete)

            do {
                try viewContext.save()
            } catch {
                // Replace this implementation with code to handle the error appropriately.
                // fatalError() causes the application to generate a crash log and terminate. You should not use this function in a shipping application, although it may be useful during development.
                let nsError = error as NSError
                fatalError("Unresolved error \(nsError), \(nsError.userInfo)")
            }
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

    private func getStringFromSecKey(_ key: SecKey) -> String? {
        // Get the key data
        var error: Unmanaged<CFError>?
        if let keyData = SecKeyCopyExternalRepresentation(key, &error) as Data? {
            // Convert the key data to a Base64-encoded string
            let keyString = keyData.base64EncodedString()
            return keyString
        } else if let error = error?.takeRetainedValue() {
            print("Error extracting key data: \(error.localizedDescription)")
        }
        return nil
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
