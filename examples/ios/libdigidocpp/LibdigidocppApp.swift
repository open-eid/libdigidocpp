// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI

@main
struct LibdigidocppApp: App {
    @State private var selection: DocumentSelection?

    var body: some Scene {
        WindowGroup {
            ContentView(selection: $selection)
                .onOpenURL { url in
                    selection = DocumentSelection(url: url)
                }
        }
    }
}
