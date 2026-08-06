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

extension DocumentViewModel: @unchecked Sendable {}

struct ContentView: View {
    @State private var dataFiles: [String] = []
    @State private var signatures: [SignatureInfo] = []
    @State private var isLoading = false
    @State private var errorMessage: String?

    let path: String

    var body: some View {
        List {
            Section("Data files") {
                ForEach(dataFiles, id: \.self) { fileName in
                    Text(fileName)
                }
            }

            ForEach(signatures) { signature in
                Section("Signature \(signature.id + 1)") {
                    LabeledContent("Signed by", value: signature.signedBy)
                    LabeledContent("Status", value: signature.status.label)
                    LabeledContent("Signing time", value: signature.signingTime)
                }
            }

            if isLoading {
                ProgressView("Opening document…")
            }

            if let errorMessage {
                Section("Error") {
                    Text(errorMessage)
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
            dataFiles = []
            signatures = []
            errorMessage = nil
            isLoading = true

            let result = await Task.detached(priority: .userInitiated) {
                Result {
                    try DocumentViewModel.initializeLibrary()
                    return try DocumentViewModel(path: path)
                }
            }.value
            guard !Task.isCancelled else {
                return
            }

            isLoading = false
            switch result {
            case let .success(document):
                dataFiles = document.dataFiles
                signatures = document.signatures
            case let .failure(error):
                errorMessage = error.localizedDescription
            }
        }
    }
}

#Preview {
    ContentView(path: Bundle.main.path(forResource: "test", ofType: "bdoc") ?? "")
}
