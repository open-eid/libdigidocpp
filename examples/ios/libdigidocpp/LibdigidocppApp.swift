// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI

@main
struct LibdigidocppApp: App {
    @State private var documentURL: URL?

    var body: some Scene {
        WindowGroup {
            ContentView(path: documentPath)
                .onOpenURL { url in
                    documentURL = url
                }
        }
    }

    private var documentPath: String {
        documentURL?.path
            ?? Bundle.main.path(forResource: "test", ofType: "bdoc")
            ?? ""
    }
}
