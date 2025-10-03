package com.pqrypt.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.widget.Toast
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
    private var senderFinalBundle: ByteArray? = null // 3.key bundle from Sender
    
    // Layered hybrid state objects
    private var senderState: Any? = null // Sender state for layered hybrid exchange
    private var receiverState: Any? = null // Receiver state for layered hybrid exchange

    // SAF saving state
    private var pickedFolderUri: Uri? = null // Persisted destination folder (tree URI)
    private var pendingOutputBytes: ByteArray? = null // Bytes queued for save
    private var pendingSuggestedName: String? = null // Filename suggestion for saving
    private var pendingSuccessToast: String? = null // Success message after save

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
            openFilePicker() // Launch SAF picker
        }

        binding.btnGenerateKeyFile.setOnClickListener { // Generate the next message or final.key
            generateKeyFile() // Dispatch to role/step-specific generation
        }
    }

    private fun updateStatus() { // Update status text based on role and current step
        val role = if (isSender) "Sender" else "Receiver" // Prefix role label
        val stepDescription = when { // Compute instruction for the current state
            isSender && currentStep == 1 -> "Step 1: Press 'Generate Key File' button to create 1.key"
            isSender && currentStep == 2 && receiverResponseBundle == null -> "Step 2: Press 'Open Key File' button and select 2.key received from receiver"
            isSender && currentStep == 2 && receiverResponseBundle != null && senderFinalBundle == null -> "Step 2: Great! Now press 'Generate Key File' button to create 3.key"
            isSender && currentStep == 3 && senderFinalBundle != null && finalSharedSecret == null -> "Step 3: Send 3.key to receiver, then press 'Generate Key File' button to create final.key"
            isSender && currentStep == 4 -> "✅ Complete! final.key has been generated and saved"
            !isSender && currentStep == 1 && senderKyberPk == null -> "Step 1: Press 'Open Key File' button and select 1.key received from sender"
            !isSender && currentStep == 2 && senderKyberPk != null -> "Step 2: Press 'Generate Key File' button to create 2.key"
            !isSender && currentStep == 3 && senderFinalBundle == null -> "Step 3: Press 'Open Key File' button and select 3.key received from sender"
            !isSender && currentStep == 3 && senderFinalBundle != null && finalSharedSecret == null -> "Step 3: Great! Now press 'Generate Key File' button to create final.key"
            !isSender && currentStep == 4 -> "✅ Complete! final.key has been generated and saved"
            else -> "Process complete"
        }
        
        binding.tvStatus.text = "$role: $stepDescription" // Render guidance
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
                    isSender && currentStep == 2 -> { // Sender consumes 2.key from receiver
                        receiverResponseBundle = keyData // Store receiver's response bundle
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh instructions
                            Toast.makeText(this@KeyExchangeProcessActivity, "2.key loaded successfully! Now press 'Generate Key File' to create 3.key", Toast.LENGTH_LONG).show() // Guide next action
                        }
                    }
                    !isSender && currentStep == 1 -> { // Receiver consumes 1.key (sender's public key)
                        senderKyberPk = keyData // Save sender's Kyber public key
                        currentStep = 2 // Advance to step 2
                        
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh UI status
                            Toast.makeText(this@KeyExchangeProcessActivity, "1.key loaded successfully! Now press 'Generate Key File' to create 2.key", Toast.LENGTH_LONG).show() // Confirmation
                        }
                    }
                    !isSender && currentStep == 3 -> { // Receiver consumes 3.key (sender's final bundle)
                        senderFinalBundle = keyData // Save sender's final bundle
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh instructions
                            Toast.makeText(this@KeyExchangeProcessActivity, "3.key loaded successfully! Now press 'Generate Key File' to create final.key", Toast.LENGTH_LONG).show() // Guide next action
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
                    isSender && currentStep == 1 -> { // Sender: create 1.key (initial keypair)
                        // Use proper PQC 4-algorithm hybrid functions (ML-KEM+X448 and HQC+P521)
                        val result = RustyCrypto.pqc4HybridInit() as Array<*> // Returns [hybrid1Key, senderState]
                        val hybrid1Key = result[0] as ByteArray // Combined ML-KEM+HQC public keys
                        val senderState = result[1] as ByteArray // Serialized sender state
                        
                        // Save hybrid keys and state
                        senderKyberPk = hybrid1Key // Store hybrid1Key as "public key"
                        senderKyberSk = senderState // Store sender state as "secret key"
                        
                        queueSaveAndPersist("1.key", hybrid1Key, "1.key generated successfully!") // Queue save of 1.key
                        currentStep = 2 // Move to step 2
                        
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh UI
                            Toast.makeText(this@KeyExchangeProcessActivity, "1.key generated! Send it to the receiver and wait for their 2.key", Toast.LENGTH_LONG).show() // Notify
                        }
                    }
                    isSender && currentStep == 2 -> { // Sender: produce 3.key after reading 2.key
                        if (receiverResponseBundle == null) { // Guard: need 2.key first
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Please read 2.key first, then press Generate", Toast.LENGTH_LONG).show() // Guidance
                            }
                            return@launch
                        }
                        // Use proper PQC 4-algorithm hybrid functions (ML-KEM+X448 and HQC+P521)
                        val result = RustyCrypto.pqc4HybridSndFinal(receiverResponseBundle!!, senderKyberSk!!) as Array<*> // Returns [finalKey(128B), hybrid3Key]
                        val finalKey = result[0] as ByteArray // 128-byte final shared secret
                        val hybrid3Key = result[1] as ByteArray // Final exchange data for receiver
                        
                        senderFinalBundle = hybrid3Key // Store 3.key for sending to receiver
                        finalSharedSecret = finalKey // Store final shared secret (128 bytes)
                        
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("3.key", hybrid3Key, "3.key generated successfully!") // Queue save
                            currentStep = 3 // Next step
                            updateStatus() // Update UI
                            Toast.makeText(this@KeyExchangeProcessActivity, "3.key generated! Send it to the receiver, then press 'Generate Key File' to create your final.key", Toast.LENGTH_LONG).show() // Instruction
                        }
                    }
                    isSender && currentStep == 3 -> { // Sender finalization: save final.key locally
                        if (finalSharedSecret == null) { // Ensure we computed it
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "No final key computed. Ensure 2.key was read and 3.key created.", Toast.LENGTH_LONG).show() // Warn
                            }
                            return@launch
                        }
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("final.key", finalSharedSecret!!, "final.key generated") // Save final.key
                            updateStatus() // UI refresh
                            Toast.makeText(this@KeyExchangeProcessActivity, "final.key generated", Toast.LENGTH_SHORT).show() // Confirm
                        }
                        currentStep = 4 // Complete
                    }
                    !isSender && currentStep == 1 -> { // Receiver: create 2.key after reading 1.key
                        if (senderKyberPk == null) { // Guard: need 1.key first
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Please read 1.key first", Toast.LENGTH_SHORT).show()
                            }
                            return@launch
                        }
                        
                        // Use proper PQC 4-algorithm hybrid functions (ML-KEM+X448 and HQC+P521)
                        val result = RustyCrypto.pqc4HybridRecv(senderKyberPk!!) as Array<*> // Returns [hybrid2Key, receiverState]
                        val hybrid2Key = result[0] as ByteArray // Combined ML-KEM+HQC ciphertexts and X448+P521 public keys
                        val receiverState = result[1] as ByteArray // Serialized receiver state
                        
                        // Save hybrid keys and state
                        receiverResponseBundle = hybrid2Key // Store hybrid2Key as response bundle
                        receiverKyberSk = receiverState // Store receiver state as "secret key"
                        
                        queueSaveAndPersist("2.key", hybrid2Key, "2.key generated successfully!") // Queue save of 2.key
                        currentStep = 3 // Move to step 3
                        
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh UI
                            Toast.makeText(this@KeyExchangeProcessActivity, "2.key generated! Send it to the sender and wait for their 3.key", Toast.LENGTH_LONG).show() // Instruction
                        }
                    }
                    !isSender && currentStep == 2 -> { // Receiver: generate 2.key response
                        if (senderKyberPk == null) { // Need 1.key first
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Error: Sender's public key not available. Please read 1.key first.", Toast.LENGTH_LONG).show() // Warn
                            }
                            return@launch
                        }
                        // Use proper PQC 4-algorithm hybrid functions (ML-KEM+X448 and HQC+P521)
                        val result = RustyCrypto.pqc4HybridRecv(senderKyberPk!!) as Array<*> // Returns [hybrid2Key, receiverState]
                        val bundledData = result[0] as ByteArray // 2.key (hybrid2Key with ML-KEM+HQC bundles)
                        receiverKyberSk = result[1] as ByteArray // Serialized receiver state
                        receiverP521Sk = ByteArray(66) { 0x33 }
                        
                        queueSaveAndPersist("2.key", bundledData, "2.key generated successfully!") // Save 2.key
                        currentStep = 3 // Move to step 3
                        
                        withContext(Dispatchers.Main) {
                            updateStatus() // Refresh UI
                            Toast.makeText(this@KeyExchangeProcessActivity, "2.key generated! Send it to the sender and wait for their 3.key", Toast.LENGTH_LONG).show() // Instruction
                        }
                    }
                    !isSender && currentStep == 3 -> { // Receiver: finalize using 3.key
                        if (senderFinalBundle == null || receiverKyberSk == null) { // Guard: need 3.key and receiver state
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@KeyExchangeProcessActivity, "Please read 3.key first", Toast.LENGTH_LONG).show() // Prompt
                            }
                            return@launch
                        }

                        // Use proper PQC 4-algorithm hybrid functions (ML-KEM+X448 and HQC+P521)
                        val finalKey = RustyCrypto.pqc4HybridRecvFinal(senderFinalBundle!!, receiverKyberSk!!) // Returns finalKey(128B)
                        finalSharedSecret = finalKey // Store final shared secret (128 bytes)
                        
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("final.key", finalKey, "final.key generated successfully!") // Save final.key
                            currentStep = 4 // Done
                            updateStatus() // UI refresh
                            Toast.makeText(this@KeyExchangeProcessActivity, "Success! final.key has been generated and saved. You can now use it for secure communication.", Toast.LENGTH_LONG).show() // Confirm
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
        CoroutineScope(Dispatchers.Main).launch { // Touch UI and launch pickers on main thread
            pendingOutputBytes = keyData // Data to write
            pendingSuggestedName = filename // File name suggestion
            pendingSuccessToast = successMsg // Success message
            if (pickedFolderUri != null) { // If we already have a folder
                saveToPickedFolder() // Save immediately
            } else {
                launchPickFolder() // Prompt user to choose destination
            }
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
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show() // Report exception
        } finally {
            pendingOutputBytes = null // Clear pending state
            pendingSuggestedName = null
            pendingSuccessToast = null
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
