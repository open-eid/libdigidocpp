// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI

@objcMembers
final class SignatureInfo: NSObject, Sendable, Identifiable {
    @objc(DigidocSignatureStatus)
    enum Status: Int {
        case valid
        case warning
        case nonQSCD
        case test
        case unknown
        case invalid

        var label: String {
            switch self {
            case .valid: "Valid"
            case .warning: "Warning"
            case .nonQSCD: "NonQSCD"
            case .test: "Test"
            case .unknown: "Unknown"
            case .invalid: "Invalid"
            }
        }
    }

    let id: Int
    let signedBy: String
    let status: Status
    let signingTime: String

    init(id: Int, signedBy: String, status: Status, signingTime: String) {
        self.id = id
        self.signedBy = signedBy
        self.status = status
        self.signingTime = signingTime
    }
}

struct ContentView: View {
    @State private var result: Result<DocumentViewModel, any Error>?

    let path: String

    var body: some View {
        List {
            switch result {
            case nil:
                Section {
                    ProgressView("Opening document…")
                        .frame(maxWidth: .infinity, alignment: .center)
                }
            case let .success(document)?:
                Section("Data files") {
                    ForEach(document.dataFiles, id: \.self) { fileName in
                        Text(fileName)
                    }
                }

                ForEach(document.signatures) { signature in
                    Section("Signature \(signature.id + 1)") {
                        LabeledContent("Signed by", value: signature.signedBy)
                        LabeledContent("Status", value: signature.status.label)
                        LabeledContent("Signing time", value: signature.signingTime)
                    }
                }
            case let .failure(error)?:
                Section("Error") {
                    Text(error.localizedDescription)
                        .foregroundStyle(.red)
                }
            }

            Text("libdigidocpp \(DocumentViewModel.libraryVersion())")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
        }
        .task(id: path) {
            result = nil
            let opened = await Task.detached(priority: .userInitiated) {
                Result {
                    try DocumentViewModel.initializeLibrary()
                    return try DocumentViewModel(path: path)
                }
            }.value
            guard !Task.isCancelled else {
                return
            }
            result = opened
        }
    }
}

#Preview {
    ContentView(path: Bundle.main.path(forResource: "test", ofType: "bdoc") ?? "")
}
