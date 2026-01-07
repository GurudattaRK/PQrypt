package com.pqrypt.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.widget.Toast
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivityKeyExchangeProcessBinding
import kotlinx.coroutines.*
import java.io.File
import java.io.FileOutputStream

class KeyExchangeProcessActivity : AppCompatActivity() { // Guided UI for 3-message layered key exchange

    private lateinit var binding: ActivityKeyExchangeProcessBinding // View binding for this screen
    private var isSender: Boolean = false // Role flag: true for Sender, false for Receiver
    private var currentStep: Int = 1 // Current step index in the flow (1..4)
    private var selectedKeyFile: Uri? = null // Last-picked key file URI from SAF
    private var selectedKeyPath: String = "" // Display name of the selected key file
    
    // Key exchange state
    private var senderKyberPk: ByteArray? = null // Sender's Kyber public key (1.key content)
    private var senderKyberSk: ByteArray? = null // Sender's Kyber secret key (kept local)
    private var senderX448Pk: ByteArray? = null // Sender's X448 public key
    private var senderX448Sk: ByteArray? = null // Sender's X448 secret key
    private var senderHqcSk: ByteArray? = null // Sender's HQC secret key
    private var senderP521Pk: ByteArray? = null // Sender's P521 public key
    private var senderP521Sk: ByteArray? = null // Sender's P521 secret key
    private var receiverKyberSk: ByteArray? = null // Receiver's Kyber secret key (local)
    private var receiverX448Sk: ByteArray? = null // Receiver's X448 secret key (local)
    private var receiverHqcSk: ByteArray? = null // Receiver's HQC secret key (local)
    private var receiverP521Sk: ByteArray? = null // Receiver's P521 secret key (local)
    private var finalSharedSecret: ByteArray? = null // Final 56-byte shared secret (final.key)
    // Bundles/files in the 3-message flow
    private var receiverResponseBundle: ByteArray? = null // 2.key bundle from Receiver
    
    // Layered hybrid state objects
    private var senderState: Any? = null // Sender state for layered hybrid exchange
    private var receiverState: Any? = null // Receiver state for layered hybrid exchange

    // SAF saving state
    private var pickedFolderUri: Uri? = null // Persisted destination folder (tree URI)
    private var pendingOutputBytes: ByteArray? = null // Bytes queued for save
    private var pendingSuggestedName: String? = null // Filename suggestion for saving
    private var pendingSuccessToast: String? = null // Success message after save
    private var pendingSecondBytes: ByteArray? = null
    private var pendingSecondName: String? = null
    private var pendingSecondSuccess: String? = null

    private val pickFolderLauncher = registerForActivityResult( // Launcher for choosing output folder
        ActivityResultContracts.StartActivityForResult()
    ) { result -> // Handle folder picker result
        if (result.resultCode == Activity.RESULT_OK) { // Proceed only on confirmation
            val treeUri = result.data?.data // Returned tree URI
            if (treeUri != null) {
                val flags = result.data?.flags ?: 0 // Granted flags
                try {
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        (flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)) // Persist R/W
                    )
                } catch (_: Exception) {}

                pickedFolderUri = treeUri // Remember for future saves
                getSharedPreferences("pqrypt_prefs", MODE_PRIVATE)
                    .edit().putString("picked_folder_uri", treeUri.toString()).apply() // Persist across sessions

                // If we have pending data to save, save it now
                if (pendingOutputBytes != null && !pendingSuggestedName.isNullOrEmpty()) {
                    saveToPickedFolder() // Complete deferred save
                }
            }
        } else {
            Toast.makeText(this, "Folder selection cancelled", Toast.LENGTH_SHORT).show() // Inform on cancel
        }
    }

    private val filePickerLauncher = registerForActivityResult( // Launcher to pick 1.key / 2.key / 3.key files
        ActivityResultContracts.StartActivityForResult()
    ) { result -> // Handle file picker result
        if (result.resultCode == Activity.RESULT_OK) { // Proceed when user picked a file
            result.data?.data?.let { uri -> // Extract content URI
                selectedKeyFile = uri // Track selection
                selectedKeyPath = getFileName(uri) // Resolve display name
                binding.tvKeyFilePath.text = "Key file: $selectedKeyPath" // Update UI
                
                // Read the key file and process based on current step
                readKeyFile(uri) // Async read + state transition
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        binding = ActivityKeyExchangeProcessBinding.inflate(layoutInflater) // Inflate binding
        setContentView(binding.root) // Attach layout

        isSender = intent.getBooleanExtra("is_sender", false) // Determine role from intent
        // Load persisted folder if available (shared with encryption screen)
        val saved = getSharedPreferences("pqrypt_prefs", MODE_PRIVATE).getString("picked_folder_uri", null) // Retrieve saved tree URI
        if (!saved.isNullOrEmpty()) {
            pickedFolderUri = Uri.parse(saved) // Restore selection
        }
        setupUI() // Wire UI
        updateStatus() // Render current step
    }

    private fun setupUI() { // Attach click handlers
        binding.btnBack.setOnClickListener { // Navigate back
            finish() // Close activity
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "pqc_process"))
        }

        binding.btnOpenKeyFile.setOnClickListener { // Pick a .key file for current step
            if (isSender && currentStep == 1) {
                generateKeyFile() // Sender starts by generating 1.key
            } else {
                openFilePicker() // Otherwise pick the required key file
            }
        }

        binding.btnGenerateKeyFile.visibility = View.GONE // Single-button flow; hide explicit generate
    }

    private fun updateStatus() { // Update status text based on role and current step
        val role = if (isSender) "Sender" else "Receiver" // Prefix role label
        val stepDescription = when { // Compute instruction for the current state
            isSender && currentStep == 1 -> "Step 1: Tap 'Start' to create 1.key"
            isSender && currentStep == 2 && receiverResponseBundle == null -> "Step 2: Tap 'Open 2.key' (bundle) from receiver to generate 3.key and final.key"
            isSender && currentStep == 3 -> "✅ Complete! 3.key and final.key generated. Send 3.key to receiver"
            !isSender && currentStep == 1 && senderKyberPk == null -> "Step 1: Tap 'Open 1.key' from sender to generate 2.key"
            !isSender && currentStep == 2 -> "Step 2: Send 2.key to sender, then tap 'Open 3.key' when you receive it"
            !isSender && currentStep >= 3 -> "✅ Complete! final.key has been generated and saved"
            else -> "Process complete"
        }
        
        binding.tvStatus.text = "$role: $stepDescription" // Render guidance
        when {
            isSender && currentStep == 1 -> binding.btnOpenKeyFile.text = "Start"
            isSender && currentStep == 2 -> binding.btnOpenKeyFile.text = "Open 2.key"
            !isSender && currentStep == 1 -> binding.btnOpenKeyFile.text = "Open 1.key"
            !isSender && currentStep == 2 -> binding.btnOpenKeyFile.text = "Open 3.key"
            else -> binding.btnOpenKeyFile.text = "Open Key File"
        }
    }

    private fun openFilePicker() { // Launch a get-content picker for any file
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply { // Build intent
            type = "*/*" // Allow any mime type
            addCategory(Intent.CATEGORY_OPENABLE) // Only openable documents
        }
        filePickerLauncher.launch(intent) // Start picker flow
    }

    private fun readKeyFile(uri: Uri) { // Read selected .key file bytes on a background thread
        CoroutineScope(Dispatchers.IO).launch { // Avoid blocking UI
            try {
                val inputStream = contentResolver.openInputStream(uri) // Open content stream
                val keyData = inputStream?.readBytes() // Read entire file
                inputStream?.close() // Close stream safely

                if (keyData != null) { // If read succeeded
                    processReadKey(keyData) // Continue with role/step-specific logic
                }
            } catch (e: Exception) { // Handle IO errors
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@KeyExchangeProcessActivity, "Error reading key file: ${e.message}", Toast.LENGTH_SHORT).show() // Notify user
                }
            }
        }
    }

    private fun processReadKey(keyData: ByteArray) { // Interpret the loaded key file by role/step
        CoroutineScope(Dispatchers.IO).launch { // Allow potential parsing to run off UI
            try {
                when {
                    isSender && currentStep == 2 -> { // Sender consumes 2.key bundle from receiver
                        receiverResponseBundle = keyData // Store receiver's bundle (package2_a||package1_b)
                        withContext(Dispatchers.Main) {
                            updateStatus()
                            Toast.makeText(this@KeyExchangeProcessActivity, "2.key bundle loaded! Generating 3.key and final.key...", Toast.LENGTH_LONG).show()
                        }
                        generateKeyFile() // Auto-generate 3.key and final.key
                    }
                    !isSender && currentStep == 1 -> { // Receiver consumes 1.key (sender's public key)
                        senderKyberPk = keyData
                        withContext(Dispatchers.Main) {
                            updateStatus()
                            Toast.makeText(this@KeyExchangeProcessActivity, "1.key loaded! Generating 2.key...", Toast.LENGTH_LONG).show()
                        }
                        generateKeyFile() // Auto-generate 2.key (bundle)
                    }
                    !isSender && currentStep == 2 -> { // Receiver consumes 3.key to finalize
                        val finalKey: ByteArray? = RustyCrypto.hybridReceiverFinalDual(keyData)
                        if (finalKey == null || finalKey.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Failed to finalize with 3.key", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        finalSharedSecret = finalKey
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("final.key", finalKey, "final.key generated successfully!")
                            currentStep = 3
                            updateStatus()
                            Toast.makeText(this@KeyExchangeProcessActivity, "final.key generated!", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            } catch (e: Exception) { // Defensive catch
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@KeyExchangeProcessActivity, "Error processing key: ${e.message}", Toast.LENGTH_SHORT).show() // Report
                }
            }
        }
    }

    private fun generateKeyFile() { // Generate or finalize keys depending on role/step
        CoroutineScope(Dispatchers.IO).launch { // Run heavy work off UI thread
            try {
                when {
                    isSender && currentStep == 1 -> { // Sender: create 1.key (package1)
                        // New protocol: hybridSenderInit() returns just package1
                        val package1: ByteArray? = RustyCrypto.hybridSenderInit()
                        if (package1 == null || package1.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Key generation failed. PQC not available.", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        
                        queueSaveAndPersist("1.key", package1, "1.key generated successfully!")
                        currentStep = 2 // Move to step 2
                        
                        withContext(Dispatchers.Main) {
                            updateStatus()
                            Toast.makeText(this@KeyExchangeProcessActivity, "1.key generated! Send it to the receiver and wait for their 2.key", Toast.LENGTH_LONG).show()
                        }
                    }
                    isSender && currentStep == 2 -> { // Sender: read 2.key bundle and generate 3.key + final.key
                        if (receiverResponseBundle == null) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Please open 2.key first", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        val result = RustyCrypto.hybridSenderThird(receiverResponseBundle!!)
                        if (result == null || result.size != 2) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Failed to process 2.key bundle.", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        val package3 = (result[0] as? ByteArray)
                        val finalKey = (result[1] as? ByteArray)
                        if (package3 == null || finalKey == null || package3.isEmpty() || finalKey.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Invalid data from native layer.", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        finalSharedSecret = finalKey
                        if (pickedFolderUri != null) {
                            withContext(Dispatchers.Main) {
                                saveDirect("3.key", package3, "3.key generated successfully!")
                                saveDirect("final.key", finalKey, "final.key generated successfully!")
                                currentStep = 3
                                updateStatus()
                                Toast.makeText(this@KeyExchangeProcessActivity, "3.key and final.key generated! Send 3.key to receiver.", Toast.LENGTH_LONG).show()
                            }
                        } else {
                            queueSaveAndPersist("3.key", package3, "3.key generated successfully!")
                            withContext(Dispatchers.Main) {
                                pendingSecondBytes = finalKey
                                pendingSecondName = "final.key"
                                pendingSecondSuccess = "final.key generated successfully!"
                                currentStep = 3
                                updateStatus()
                                Toast.makeText(this@KeyExchangeProcessActivity, "3.key and final.key generated! Send 3.key to receiver.", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                    !isSender && currentStep == 1 -> { // Receiver: create 2.key bundle after reading 1.key
                        if (senderKyberPk == null) { // Guard: need 1.key first
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Please read 1.key first", Toast.LENGTH_SHORT).show()
                            }
                            return@launch
                        }
                        val bundle: ByteArray? = RustyCrypto.hybridReceiverDual(senderKyberPk!!)
                        if (bundle == null || bundle.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Failed to generate 2.key bundle.", Toast.LENGTH_LONG).show()
                            }
                            return@launch
                        }
                        queueSaveAndPersist("2.key", bundle, "2.key generated successfully!")
                        currentStep = 2
                        
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh UI
                            Toast.makeText(this@KeyExchangeProcessActivity, "2.key generated! Send it to sender. Then open 3.key when you receive it.", Toast.LENGTH_LONG).show()
                        }
                    }
                    
                    else -> { // Any other state
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@KeyExchangeProcessActivity, "Invalid step for key generation", Toast.LENGTH_SHORT).show() // Inform
                        }
                    }
                }
            } catch (e: Exception) { // Catch and surface errors
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@KeyExchangeProcessActivity, "Error generating key: ${e.message}", Toast.LENGTH_LONG).show() // Report
                    // Don't finish the activity, just show the error
                }
            }
        }
    }

    private fun queueSaveAndPersist(filename: String, keyData: ByteArray, successMsg: String) { // Prepare and trigger save
        CoroutineScope(Dispatchers.Main).launch {
            if (pickedFolderUri != null) {
                saveDirect(filename, keyData, successMsg)
            } else {
                pendingOutputBytes = keyData
                pendingSuggestedName = filename
                pendingSuccessToast = successMsg
                launchPickFolder()
            }
        }
    }

    private fun saveDirect(filename: String, keyData: ByteArray, successMsg: String) {
        val folderUri = pickedFolderUri ?: return
        try {
            val outUri = createUniqueDocumentCopySuffix(folderUri, "application/octet-stream", filename)
            if (outUri != null) {
                contentResolver.openOutputStream(outUri)?.use { it.write(keyData) }
                binding.tvGeneratedFilePath.text = "Saved to: $outUri"
                Toast.makeText(this, successMsg, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun launchPickFolder() { // Ask the user to choose a save folder
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply { // Build tree picker intent
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION) // Persist R/W
            // Try to hint initial location to Documents/PQrypt
            try {
                val hinted = buildPQryptInitialTreeUri() // Construct best-effort initial location
                if (hinted != null) {
                    putExtra("android.provider.extra.INITIAL_URI", hinted) // Provide hint
                }
            } catch (_: Exception) {}
        }
        pickFolderLauncher.launch(intent) // Launch picker
    }

    // Best-effort to hint the picker at /storage/emulated/0/Documents/PQrypt
    private fun buildPQryptInitialTreeUri(): Uri? { // Suggest Documents/PQrypt as initial folder
        return try {
            // Ensure the directory exists so the picker can show it
            val docs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) // /storage/emulated/0/Documents
            val pqrypt = File(docs, "PQrypt") // Documents/PQrypt
            if (!pqrypt.exists()) pqrypt.mkdirs() // Create if missing

            val authority = "com.android.externalstorage.documents" // Documents provider authority
            val docId = "primary:Documents/PQrypt" // Tree doc ID
            android.provider.DocumentsContract.buildTreeDocumentUri(authority, docId) // Build tree URI
        } catch (_: Exception) {
            null // Best-effort only
        }
    }

    private fun saveToPickedFolder() { // Persist queued bytes to the chosen folder
        val folderUri = pickedFolderUri // Destination tree URI
        val bytes = pendingOutputBytes // Data to write
        val name = pendingSuggestedName // Target filename
        if (folderUri == null || bytes == null || name.isNullOrEmpty()) return // Guard

        try {
            val outUri = createUniqueDocumentCopySuffix(folderUri, "application/octet-stream", name) // Create new file
            if (outUri != null) {
                contentResolver.openOutputStream(outUri)?.use { it.write(bytes) } // Write bytes
                binding.tvGeneratedFilePath.text = "Saved to: $outUri" // Show destination
                Toast.makeText(this, pendingSuccessToast ?: "Saved", Toast.LENGTH_SHORT).show() // Notify
            } else {
                Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show() // Report error
            }
            if (pendingSecondBytes != null && !pendingSecondName.isNullOrEmpty()) {
                val outUri2 = createUniqueDocumentCopySuffix(folderUri, "application/octet-stream", pendingSecondName!!)
                if (outUri2 != null) {
                    contentResolver.openOutputStream(outUri2)?.use { it.write(pendingSecondBytes) }
                    binding.tvGeneratedFilePath.text = "Saved to: $outUri2"
                    Toast.makeText(this, pendingSecondSuccess ?: "Saved", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show() // Report exception
        } finally {
            pendingOutputBytes = null // Clear pending state
            pendingSuggestedName = null
            pendingSuccessToast = null
            pendingSecondBytes = null
            pendingSecondName = null
            pendingSecondSuccess = null
        }
    }

    // Create a document, deleting existing file if it exists
    private fun createUniqueDocumentCopySuffix(treeUri: Uri, mime: String, desiredName: String): Uri? { // Create file, overwriting if exists
        val treeDoc = androidx.documentfile.provider.DocumentFile.fromTreeUri(this, treeUri) ?: return null // Wrap tree
        
        // Check if file already exists and delete it
        val existingFile = treeDoc.findFile(desiredName)
        if (existingFile != null && existingFile.exists()) {
            existingFile.delete() // Delete existing file to prevent conflicts
        }

        val parentDocId = android.provider.DocumentsContract.getTreeDocumentId(treeUri) // Parent doc ID
        val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId) // Parent URI
        return android.provider.DocumentsContract.createDocument(contentResolver, parentDocUri, mime, desiredName) // Create file with exact name
    }

    private fun getFileName(uri: Uri): String { // Resolve a display name for a given content/file URI
        var result: String? = null // Working variable
        if (uri.scheme == "content") { // Prefer content resolver display name
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use { // Auto-close when done
                if (it.moveToFirst()) { // Move to first row
                    val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME) // Column index
                    if (nameIndex >= 0) { // Ensure column is present
                        result = it.getString(nameIndex) // Use provider-supplied name
                    }
                }
            }
        }
        if (result == null) { // Fallback to path parsing when not a content scheme
            result = uri.path // Raw path from URI
            val cut = result?.lastIndexOf('/') // Find last slash
            if (cut != -1) {
                result = result?.substring(cut!! + 1) // Take basename
            }
        }
        return result ?: "unknown_file" // Final fallback
    }
}
