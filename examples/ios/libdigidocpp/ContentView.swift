// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI
import UniformTypeIdentifiers

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

struct DocumentSelection: Equatable {
    let url: URL
    let id = UUID()
}

struct ContentView: View {
    @Binding var selection: DocumentSelection?
    @State private var result: Result<DocumentViewModel, any Error>?
    @State private var isImporting = false

    var body: some View {
        List {
            Section {
                Button("Open document", systemImage: "folder") {
                    isImporting = true
                }
            }

            switch result {
            case nil:
                if selection != nil {
                    Section {
                        ProgressView("Opening document…")
                            .frame(maxWidth: .infinity, alignment: .center)
                    }
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
        .fileImporter(isPresented: $isImporting,
                      allowedContentTypes: [UTType(exportedAs: "ee.ria.bdoc")]) { picked in
            switch picked {
            case let .success(url):
                selection = DocumentSelection(url: url)
            case let .failure(error):
                result = .failure(error)
            }
        }
        .task(id: selection) {
            guard let url = selection?.url else {
                return
            }
            result = nil
            let opened = await Task.detached(priority: .userInitiated) {
                Result {
                    try DocumentViewModel.initializeLibrary()
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer {
                        if accessing {
                            url.stopAccessingSecurityScopedResource()
                        }
                    }
                    return try DocumentViewModel(path: url.path(percentEncoded: false))
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
    ContentView(selection: .constant(nil))
}
