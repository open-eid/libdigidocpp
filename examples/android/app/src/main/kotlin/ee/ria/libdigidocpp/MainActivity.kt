// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

package ee.ria.libdigidocpp

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.zip.ZipInputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                DocumentScreen()
            }
        }
    }

    companion object {
        init {
            System.loadLibrary("digidoc_java")
        }
    }
}

data class SignatureInfo(
    val signedBy: String,
    val signingTime: String,
    val status: String,
    val diagnostics: String,
)

data class DocumentInfo(
    val dataFiles: List<String>,
    val signatures: List<SignatureInfo>,
)

sealed interface DocumentState {
    data object Empty : DocumentState
    data object Loading : DocumentState
    data class Loaded(val document: DocumentInfo) : DocumentState
    data class Failed(val message: String) : DocumentState
}

private object Library {
    private var initialized = false

    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        val cache = context.cacheDir.toPath()
        ZipInputStream(context.resources.openRawResource(R.raw.schema)).use { zip ->
            generateSequence { zip.nextEntry }.forEach { entry ->
                Files.copy(zip, cache.resolve(entry.name), StandardCopyOption.REPLACE_EXISTING)
            }
        }
        digidoc.initializeLib("libdigidocpp Android", cache.toString())
        initialized = true
    }
}

private fun openDocument(context: Context, uri: Uri): DocumentInfo {
    Library.initialize(context)
    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
        ?.let { File(it).name }
        ?: "document"
    val dir = Files.createDirectories(context.cacheDir.toPath().resolve("open"))
    val path = dir.resolve(name)
    context.contentResolver.openInputStream(uri)?.use { input ->
        Files.copy(input, path, StandardCopyOption.REPLACE_EXISTING)
    } ?: error("Cannot read the document")

    try {
        val container = Container.open(path.toString())
        try {
            return DocumentInfo(
                dataFiles = container.dataFiles().map { it.fileName() },
                signatures = container.signatures().map { signature ->
                    val validator = Signature.Validator(signature)
                    SignatureInfo(
                        signedBy = signature.signedBy(),
                        signingTime = signature.trustedSigningTime(),
                        status = validator.status().toString(),
                        diagnostics = validator.diagnostics(),
                    )
                },
            )
        } finally {
            container.delete()
        }
    } finally {
        Files.deleteIfExists(path)
    }
}

@Composable
fun DocumentScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DocumentState>(DocumentState.Empty) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        state = DocumentState.Loading
        scope.launch {
            state = try {
                DocumentState.Loaded(withContext(Dispatchers.IO) { openDocument(context, uri) })
            } catch (e: Exception) {
                DocumentState.Failed(e.message ?: e.toString())
            }
        }
    }

    Scaffold { innerPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Button(
                    onClick = { picker.launch(arrayOf("*/*")) },
                    enabled = state != DocumentState.Loading,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Open document")
                }
            }
            when (val current = state) {
                DocumentState.Empty -> {}
                DocumentState.Loading -> item {
                    CircularProgressIndicator(modifier = Modifier.fillMaxWidth().wrapContentWidth())
                }
                is DocumentState.Failed -> item {
                    Text(current.message, color = MaterialTheme.colorScheme.error)
                }
                is DocumentState.Loaded -> {
                    item { Section("Data files", current.document.dataFiles) }
                    items(current.document.signatures.withIndex().toList()) { (index, signature) ->
                        Section("Signature ${index + 1}", listOfNotNull(
                            "Signed by: ${signature.signedBy}",
                            "Status: ${signature.status}",
                            "Signing time: ${signature.signingTime}",
                            signature.diagnostics.takeIf { it.isNotEmpty() }?.let { "Diagnostics: $it" },
                        ))
                    }
                }
            }
            item {
                Text(
                    "libdigidocpp ${digidoc.version()}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth().wrapContentWidth(),
                )
            }
        }
    }
}

@Composable
private fun Section(title: String, lines: List<String>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            lines.forEach { Text(it) }
        }
    }
}
