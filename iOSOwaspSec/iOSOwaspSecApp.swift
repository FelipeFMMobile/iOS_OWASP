//
//  iOSOwaspSecApp.swift
//  iOSOwaspSec
//
//  Created by Felipe Menezes on 18/09/24.
//

import SwiftUI

@main
struct iOSOwaspSecApp: App {
    let persistenceController = PersistenceController.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
    }
}
