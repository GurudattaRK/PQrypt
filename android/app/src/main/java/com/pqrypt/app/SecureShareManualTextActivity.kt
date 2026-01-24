package com.pqrypt.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.pqrypt.app.databinding.ActivitySecureShareManualTextBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.os.ParcelFileDescriptor
import android.os.Environment
import java.io.File
import androidx.documentfile.provider.DocumentFile

class SecureShareManualTextActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareManualTextBinding
    private var contentType = "text"
    private var transferMode = "manual"
    private var role = "sender"
    private var isSender = true
    private var currentStep = 1
    private val P3_LEN = 66098
    
    // File and key management
    private var finalSharedSecret: ByteArray? = null
    private var lastOutputPath: String? = null
    private var etInputText: String = ""
    private var package3Bytes: ByteArray? = null
    private var tempTextFile: File? = null
    private var senderKeyUri: Uri? = null
    
    // SAF saving state (copied from working PQC KeyExchangeProcessActivity)
    private var pickedFolderUri: Uri? = null
    private var pendingOutputBytes: ByteArray? = null
    private var pendingSuggestedName: String? = null
    private var pendingSuccessToast: String? = null

    private val keyFilePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                handleKeyFileSelection(uri)
            }
        }
    }

    private val pickFolderLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val treeUri = result.data?.data
            if (treeUri != null) {
                val flags = result.data?.flags ?: 0
                try {
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        (flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION))
                    )
                } catch (_: Exception) {}

                pickedFolderUri = treeUri
                getSharedPreferences("pqrypt_prefs", MODE_PRIVATE)
                    .edit().putString("picked_folder_uri", treeUri.toString()).apply()

                if (pendingOutputBytes != null && !pendingSuggestedName.isNullOrEmpty()) {
                    saveToPickedFolder()
                }
            }
        } else {
            Toast.makeText(this, "Folder selection cancelled", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecureShareManualTextBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Get intent extras
        contentType = intent.getStringExtra("content_type") ?: "text"
        transferMode = intent.getStringExtra("transfer_mode") ?: "manual"
        role = intent.getStringExtra("role") ?: "sender"
        isSender = role == "sender"

        // Load persisted folder if available (same as PQC)
        val saved = getSharedPreferences("pqrypt_prefs", MODE_PRIVATE).getString("picked_folder_uri", null)
        if (!saved.isNullOrEmpty()) {
            pickedFolderUri = Uri.parse(saved)
        }

        // Set initial step
        currentStep = 1

        setupUI()
        updateUI()
    }

    private fun setupUI() {
        binding.tvRole.text = role.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, SecureShareHelpActivity::class.java).putExtra("screen", "manual_text"))
        }

        // Single action button for main flow
        binding.btnStep1.setOnClickListener {
            when {
                isSender && currentStep == 1 -> generateStep1Key()
                isSender && currentStep == 2 -> openKeyFile("2.key")
                !isSender && currentStep == 1 -> openKeyFile("1.key")
                !isSender && currentStep == 2 -> openEncryptedTextFile()
            }
        }


        // Output folder button removed - users already know where they saved files

        // Extra button - cleanup only
        binding.btnCleanup.setOnClickListener {
            cleanupIntermediateFiles()
        }

        // Text input character counter (sender only)
        if (isSender) {
            binding.etTextInput.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    binding.tvCharCount.text = "${s?.length ?: 0} characters"
                }
            })
        }
    }

    private fun updateUI() {
        // Show/hide text input/display based on role
        binding.llTextInput.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.llTextDisplay.visibility = if (!isSender) View.VISIBLE else View.GONE
        
        // Update main action button
        binding.btnStep1.text = when {
            isSender && currentStep == 1 -> "Generate 1.key"
            isSender && currentStep == 2 -> "Open 2.key from Receiver"
            !isSender && currentStep == 1 -> "Open 1.key from Sender"
            !isSender && currentStep == 2 -> "Open Encrypted File (.pqrypt)"
            else -> "Process Complete"
        }
        
        binding.btnStep1.isEnabled = currentStep <= 2
        
        // Update status text
        binding.tvStatus.text = when {
            isSender && currentStep == 1 -> "Step 1: Enter your text message above, then press 'Generate 1.key'"
            isSender && currentStep == 2 -> "Step 2: Send 1.key to receiver and wait for their 2.key. Once received, press 'Open 2.key from Receiver' button"
            isSender && currentStep > 2 -> "✅ Success! Your text has been encrypted. Send the encrypted .pqrypt file to the receiver"
            !isSender && currentStep == 1 -> "Step 1: Wait for sender's 1.key file. Once received, press 'Open 1.key from Sender' button (2.key will auto-generate)"
            !isSender && currentStep == 2 -> "Step 2: Send 2.key to sender. Once you receive the encrypted file, press 'Open Encrypted File (.pqrypt)' to decrypt"
            else -> "✅ Process complete! Message successfully decrypted"
        }
    }

    private fun generateStep1Key() {
        if (!isSender) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                resetStates()
                
                etInputText = binding.etTextInput.text.toString()
                if (etInputText.trim().isEmpty()) {
                    withContext(Dispatchers.Main) {
                        showError("Please enter a text message")
                    }
                    return@launch
                }

                val tmp = File.createTempFile("secure_share_text_", ".txt", cacheDir)
                tmp.writeText(etInputText)
                tempTextFile = tmp

                val package1 = RustyCrypto.hybridSenderInit()
                
                withContext(Dispatchers.Main) {
                    saveKeyFile(package1, "1.key")
                    binding.tvStep1Result.text = "✅ 1.key generated successfully! Send this file to the receiver"
                    binding.tvStep1Result.visibility = View.VISIBLE
                    currentStep = 2
                    updateUI()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Error generating 1.key: ${e.message}")
                }
            }
        }
    }

    private fun handleKeyFileSelection(uri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyData = readFileBytes(uri)
                if (keyData == null || keyData.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        showError("Failed to read key file")
                    }
                    return@launch
                }

                when {
                    // Receiver opening 1.key -> generate 2.key bundle ONLY (dual mutual exchange)
                    !isSender && currentStep == 1 -> {
                        resetStates()
                        senderKeyUri = uri
                        val package2 = RustyCrypto.hybridReceiverDual(keyData)

                        withContext(Dispatchers.Main) {
                            if (package2 != null && package2.isNotEmpty()) {
                                saveKeyFile(package2, "2.key")
                                binding.tvStep1Result.text = "✅ 2.key generated! Send 2.key to sender, then wait for encrypted .pqrypt file"
                                binding.tvStep1Result.visibility = View.VISIBLE
                                currentStep = 2
                                updateUI()
                            } else {
                                showError("Failed to generate 2.key")
                            }
                        }
                    }

                    // Sender opening 2.key -> generate 3.key + final key, encrypt text, embed 3.key into encrypted payload
                    isSender && currentStep == 2 -> {
                        withContext(Dispatchers.Main) {
                            binding.tvStep1Result.text = "Processing 2.key..."
                            binding.tvStep1Result.visibility = View.VISIBLE
                        }

                        val result = RustyCrypto.hybridSenderThird(keyData)
                        if (result == null || result.size != 2) {
                            withContext(Dispatchers.Main) {
                                showError("Failed to process 2.key")
                            }
                            return@launch
                        }
                        val p3 = result[0] as? ByteArray
                        val fk = result[1] as? ByteArray
                        if (p3 == null || fk == null || p3.isEmpty() || fk.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                showError("Invalid data from native layer")
                            }
                            return@launch
                        }
                        package3Bytes = p3
                        finalSharedSecret = fk

                        withContext(Dispatchers.Main) {
                            binding.tvStep1Result.text = "✅ Final key ready. Encrypting message..."
                            binding.tvStep1Result.visibility = View.VISIBLE
                        }
                        performTextEncryption()
                    }

                    // Receiver opening encrypted text -> auto-decrypt and display
                    !isSender && currentStep == 2 -> {
                        performTextDecryption(uri, keyData)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Error processing key: ${e.message}")
                }
            }
        }
    }

    private fun performTextEncryption() {
        if (finalSharedSecret == null) {
            showError("Missing text or encryption key")
            return
        }

        val inputFile = tempTextFile
        if (inputFile == null || !inputFile.exists()) {
            showError("Text file missing")
            return
        }

        val p3 = package3Bytes
        if (p3 == null || p3.isEmpty()) {
            showError("Missing 3.key data")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                withContext(Dispatchers.Main) {
                    if (pickedFolderUri == null) {
                        binding.tvStatus.text = "Select destination folder before encryption"
                        launchPickFolder()
                    }
                }
                var attempts = 0
                while (pickedFolderUri == null && attempts < 120) {
                    kotlinx.coroutines.delay(1000)
                    attempts++
                }
                if (pickedFolderUri == null) {
                    withContext(Dispatchers.Main) { showError("No destination folder selected") }
                    return@launch
                }
                // Create output file in cache
                val outputFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                
                val inputFd = ParcelFileDescriptor.open(inputFile, ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(outputFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val success = try {
                    RustyCrypto.doubleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                if (success == RustyCrypto.CRYPTO_SUCCESS) {
                    val encryptedBytes = outputFile.readBytes()

                    val combined = ByteArray(p3.size + encryptedBytes.size)
                    System.arraycopy(p3, 0, combined, 0, p3.size)
                    System.arraycopy(encryptedBytes, 0, combined, p3.size, encryptedBytes.size)

                    withContext(Dispatchers.Main) {
                        saveKeyFile(combined, "text.pqrypt")
                        binding.tvStep1Result.text = "Text encrypted and saved"
                        binding.tvStep1Result.visibility = View.VISIBLE
                        currentStep = 4
                        updateUI()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        showError("Text encryption failed")
                    }
                }

                outputFile.delete()
                try { inputFile.delete() } catch (_: Exception) {}
                tempTextFile = null
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Encryption error: ${e.message}")
                }
            }
        }
    }

    private fun performTextDecryption(encryptedUri: Uri, encryptedData: ByteArray) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                var decryptBytes = encryptedData

                val magic = byteArrayOf('P'.code.toByte(),'Q'.code.toByte(),'R'.code.toByte(),'Y'.code.toByte(),'P'.code.toByte(),'T'.code.toByte())
                val isPlain = decryptBytes.size >= 6 && decryptBytes.copyOfRange(0, 6).contentEquals(magic)

                if (!isPlain) {
                    if (decryptBytes.size < P3_LEN + 73) {
                        withContext(Dispatchers.Main) { showError("Invalid encrypted file (too small for combined)") }
                        return@launch
                    }

                    val p3 = decryptBytes.copyOfRange(0, P3_LEN)
                    val fk = RustyCrypto.hybridReceiverFinalDual(p3)
                    if (fk == null || fk.isEmpty()) {
                        withContext(Dispatchers.Main) { showError("Failed to finalize with embedded 3.key") }
                        return@launch
                    }
                    finalSharedSecret = fk
                    decryptBytes = decryptBytes.copyOfRange(P3_LEN, decryptBytes.size)
                } else {
                    if (finalSharedSecret == null) {
                        withContext(Dispatchers.Main) { showError("No decryption key available. Please open 1.key first.") }
                        return@launch
                    }
                }

                // Write encrypted payload to temp file
                val inputFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                inputFile.writeBytes(decryptBytes)
                
                val outputFile = File.createTempFile("decrypted_", ".txt", cacheDir)
                
                val inputFd = ParcelFileDescriptor.open(inputFile, ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(outputFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val secret = finalSharedSecret
                if (secret == null || secret.isEmpty()) {
                    withContext(Dispatchers.Main) { showError("No decryption key available") }
                    inputFile.delete()
                    outputFile.delete()
                    return@launch
                }

                val success = try {
                    RustyCrypto.doubleDecryptFd(secret, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                if (success == RustyCrypto.CRYPTO_SUCCESS) {
                    val decryptedBytes = outputFile.readBytes()
                    val decryptedText = String(decryptedBytes)
                    
                    withContext(Dispatchers.Main) {
                        // Display decrypted text
                        binding.tvDecryptedText.text = decryptedText
                        binding.tvStep1Result.text = "Text decrypted successfully!"
                        binding.tvStep1Result.visibility = View.VISIBLE

                        currentStep = 4
                        updateUI()
                    }

                    deleteAfterDecrypt(encryptedUri)
                } else {
                    withContext(Dispatchers.Main) {
                        val errorMessage = when (success) {
                            RustyCrypto.CRYPTO_ERROR_DECRYPTION_FAILED -> "Authentication/decryption failed. This may be due to file corruption, tampering, or wrong file selection."
                            RustyCrypto.CRYPTO_ERROR_INVALID_INPUT -> "Invalid encrypted file. The file may be corrupted or not a valid encrypted text."
                            RustyCrypto.CRYPTO_ERROR_NULL_POINTER -> "File access error. Please check file permissions."
                            else -> "Text decryption failed. This may be due to file corruption, tampering, or wrong file selection."
                        }
                        showError(errorMessage)
                    }
                }
                
                inputFile.delete()
                outputFile.delete()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Decryption error: ${e.message}")
                }
            }
        }
    }

    private fun deleteAfterDecrypt(encryptedUri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                try {
                    val doc = DocumentFile.fromSingleUri(this@SecureShareManualTextActivity, encryptedUri)
                    doc?.delete()
                } catch (_: Exception) {}

                senderKeyUri?.let { keyUri ->
                    try {
                        val keyDoc = DocumentFile.fromSingleUri(this@SecureShareManualTextActivity, keyUri)
                        keyDoc?.delete()
                    } catch (_: Exception) {}
                }

                pickedFolderUri?.let { folderUri ->
                    val treeDoc = DocumentFile.fromTreeUri(this@SecureShareManualTextActivity, folderUri)
                    treeDoc?.findFile("1.key")?.delete()
                    treeDoc?.findFile("2.key")?.delete()
                    treeDoc?.findFile("3.key")?.delete()
                    treeDoc?.findFile("text.pqrypt")?.delete()
                }
            } finally {
                resetStates()
            }
        }
    }

    private fun openKeyFile(expectedFile: String) {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        keyFilePickerLauncher.launch(intent)
    }

    private fun openEncryptedTextFile() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        keyFilePickerLauncher.launch(intent)
    }

    private fun resetStates() {
        finalSharedSecret?.fill(0)
        finalSharedSecret = null
        package3Bytes?.fill(0)
        package3Bytes = null
        senderKeyUri = null
        tempTextFile?.let {
            try { it.delete() } catch (_: Exception) {}
        }
        tempTextFile = null
    }

    private fun saveKeyFile(keyData: ByteArray, fileName: String) {
        // Use SAF like PQC key exchange (eliminates file exists errors)
        queueSaveAndPersist(fileName, keyData, "$fileName saved successfully")
    }

    private fun readFileBytes(uri: Uri): ByteArray? {
        return try {
            contentResolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (e: Exception) {
            null
        }
    }

    // SAF functions copied from working PQC KeyExchangeProcessActivity
    private fun queueSaveAndPersist(filename: String, keyData: ByteArray, successMsg: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            pendingOutputBytes = keyData
            pendingSuggestedName = filename
            pendingSuccessToast = successMsg
            if (pickedFolderUri != null) {
                saveToPickedFolder()
            } else {
                launchPickFolder()
            }
        }
    }

    private fun launchPickFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
            try {
                val hinted = buildPQryptInitialTreeUri()
                if (hinted != null) {
                    putExtra("android.provider.extra.INITIAL_URI", hinted)
                }
            } catch (_: Exception) {}
        }
        pickFolderLauncher.launch(intent)
    }

    private fun buildPQryptInitialTreeUri(): Uri? {
        return try {
            val docs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
            val pqrypt = File(docs, "PQrypt")
            if (!pqrypt.exists()) pqrypt.mkdirs()

            val authority = "com.android.externalstorage.documents"
            val docId = "primary:Documents/PQrypt"
            android.provider.DocumentsContract.buildTreeDocumentUri(authority, docId)
        } catch (_: Exception) {
            null
        }
    }

    private fun saveToPickedFolder() {
        val folderUri = pickedFolderUri
        val bytes = pendingOutputBytes
        val name = pendingSuggestedName
        if (folderUri == null || bytes == null || name.isNullOrEmpty()) return

        try {
            val outUri = createUniqueDocumentCopySuffix(folderUri, "application/octet-stream", name)
            if (outUri != null) {
                contentResolver.openOutputStream(outUri)?.use { it.write(bytes) }
                binding.tvStatus.text = pendingSuccessToast ?: "Saved"
                Toast.makeText(this, pendingSuccessToast ?: "Saved", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
        } finally {
            pendingOutputBytes = null
            pendingSuggestedName = null
            pendingSuccessToast = null
        }
    }

    private fun createUniqueDocumentCopySuffix(treeUri: Uri, mime: String, desiredName: String): Uri? {
        val treeDoc = DocumentFile.fromTreeUri(this, treeUri) ?: return null
        
        // Check if file already exists and delete it (this works reliably with SAF)
        val existingFile = treeDoc.findFile(desiredName)
        if (existingFile != null && existingFile.exists()) {
            existingFile.delete() // SAF delete works properly
        }

        val parentDocId = android.provider.DocumentsContract.getTreeDocumentId(treeUri)
        val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
        return android.provider.DocumentsContract.createDocument(contentResolver, parentDocUri, mime, desiredName)
    }

    private fun cleanupIntermediateFiles() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                var deletedCount = 0
                
                // Clean cache directory only (no external storage issues)
                cacheDir.listFiles()?.forEach { file ->
                    if (file.name.startsWith("temp_") || 
                        file.name.startsWith("input_") || 
                        file.name.startsWith("encrypted_") ||
                        file.name.startsWith("decrypted_") ||
                        file.name.endsWith(".tmp")) {
                        if (file.delete()) deletedCount++
                    }
                }
                
                // Clean up key files in picked folder if available
                pickedFolderUri?.let { folderUri ->
                    val treeDoc = DocumentFile.fromTreeUri(this@SecureShareManualTextActivity, folderUri)
                    treeDoc?.listFiles()?.forEach { file ->
                        val name = file.name ?: ""
                        if (name.endsWith(".key") || name.endsWith(".encrypted") || 
                            name.endsWith(".txt") || name.endsWith(".pqrypt2")) {
                            if (file.delete()) deletedCount++
                        }
                    }
                }
                
                // Reset states
                resetStates()
                
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@SecureShareManualTextActivity, 
                        "Cleaned up $deletedCount files", 
                        Toast.LENGTH_SHORT).show()
                    binding.tvStatus.text = "Cleanup completed"
                    
                    // Clear text fields
                    binding.etTextInput.setText("")
                    binding.tvDecryptedText.text = ""
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@SecureShareManualTextActivity, 
                        "Cleanup completed", 
                        Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun showError(message: String) {
        binding.tvStatus.text = "Error: $message"
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
