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
import com.pqrypt.app.databinding.ActivitySecureShareManualFileBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.os.ParcelFileDescriptor
import android.os.Environment
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import androidx.documentfile.provider.DocumentFile

class SecureShareManualFileActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareManualFileBinding
    private var contentType = "file"
    private var transferMode = "manual"
    private var role = "sender"
    private var isSender = true
    private var currentStep = 1
    private val P3_LEN = 66098
    
    // File and key management
    private var selectedFileUri: Uri? = null
    private var selectedFilePath = ""
    private var finalSharedSecret: ByteArray? = null
    private var lastOutputPath: String? = null
    private var package3Bytes: ByteArray? = null
    
    // SAF saving state (copied from working PQC KeyExchangeProcessActivity)
    private var pickedFolderUri: Uri? = null
    private var pendingOutputBytes: ByteArray? = null
    private var pendingSuggestedName: String? = null
    private var pendingSuccessToast: String? = null
    private var pendingShowPathInResult: Boolean = false

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                selectedFileUri = uri
                selectedFilePath = getFileName(uri) ?: "Unknown file"
                binding.tvSelectedFile.text = "Selected: $selectedFilePath"
                updateUI()
            }
        }
    }

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
        binding = ActivitySecureShareManualFileBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Get intent extras
        contentType = intent.getStringExtra("content_type") ?: "file"
        transferMode = intent.getStringExtra("transfer_mode") ?: "manual"
        role = intent.getStringExtra("role") ?: "sender"
        isSender = role == "sender"

        // Load persisted folder if available (same as PQC)
        val saved = getSharedPreferences("pqrypt_prefs", MODE_PRIVATE).getString("picked_folder_uri", null)
        if (!saved.isNullOrEmpty()) {
            pickedFolderUri = Uri.parse(saved)
        }

        // Set initial step based on role
        currentStep = 1

        setupUI()
        updateUI()
    }

    private fun setupUI() {
        binding.tvRole.text = "Role: ${role.replaceFirstChar { it.uppercase() }}"
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, SecureShareHelpActivity::class.java).putExtra("screen", "manual_file"))
        }

        // File selection button (sender only)
        binding.btnChooseFile.setOnClickListener {
            openFilePicker()
        }

        // Single action button for main flow
        binding.btnStep1.setOnClickListener {
            when {
                isSender && currentStep == 1 -> generateStep1Key()
                isSender && currentStep == 2 -> openKeyFile("2.key")
                !isSender && currentStep == 1 -> openKeyFile("1.key")
                !isSender && currentStep == 2 -> openEncryptedFilePicker()
            }
        }


        // Output folder button removed - users already know where they saved files

        // Extra button - cleanup only
        binding.btnCleanup.setOnClickListener {
            cleanupIntermediateFiles()
        }
    }

    private fun updateUI() {
        // Show/hide file selection for sender
        binding.llFileSelection.visibility = if (isSender && currentStep == 1) View.VISIBLE else View.GONE
        
        // Update main action button
        binding.btnStep1.text = when {
            isSender && currentStep == 1 -> "Generate 1.key"
            isSender && currentStep == 2 -> "Open 2.key from Receiver"
            !isSender && currentStep == 1 -> "Open 1.key from Sender"
            !isSender && currentStep == 2 -> "Open Encrypted File"
            else -> "Process Complete"
        }
        
        binding.btnStep1.isEnabled = when {
            isSender && currentStep == 1 && selectedFileUri == null -> false
            currentStep > 2 -> false
            else -> true
        }
        
        // Update status text
        binding.tvStatus.text = when {
            isSender && currentStep == 1 -> "Step 1: Press 'Choose File' to select a file, then press 'Generate 1.key' button"
            isSender && currentStep == 2 -> "Step 2: Send 1.key to receiver and wait for their 2.key. Once received, press 'Open 2.key from Receiver' button"
            isSender && currentStep > 2 -> "✅ Success! Your file has been encrypted. Share the encrypted file with the receiver"
            !isSender && currentStep == 1 -> "Step 1: Wait for sender's 1.key file. Once received, press 'Open 1.key from Sender' button (2.key will be generated)"
            !isSender && currentStep == 2 -> "Step 2: Send 2.key to sender. When you receive 3.key, open it first to finalize, then open the encrypted file to decrypt"
            else -> "✅ Process complete! File successfully decrypted"
        }
    }

    private fun generateStep1Key() {
        if (!isSender || selectedFileUri == null) {
            showError("Please select a file first")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                resetStates()
                
                val publicKey: ByteArray? = RustyCrypto.hybridSenderInit()
                if (publicKey == null || publicKey.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        showError("Key generation failed. PQC not available.")
                    }
                    return@launch
                }
                
                withContext(Dispatchers.Main) {
                    queueSaveAndPersist("1.key", publicKey, "1.key generated successfully")
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
                    // Receiver opening 1.key -> generate 2.key ONLY (no final key yet)
                    !isSender && currentStep == 1 -> {
                        resetStates()
                        val package2 = RustyCrypto.hybridReceiverDual(keyData)
                        if (package2 == null || package2.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                showError("Failed to generate 2.key. PQC not available.")
                            }
                            return@launch
                        }
                        
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("2.key", package2, "2.key generated - Share with sender")
                            binding.tvStep1Result.text = "2.key generated. After you receive 3.key from sender, open it to finalize, then open the encrypted file to decrypt"
                            binding.tvStep1Result.visibility = View.VISIBLE
                            currentStep = 2
                            updateUI()
                        }
                    }
                    
                    // Sender opening 2.key -> generate 3.key and final key (in memory), then encrypt file
                    isSender && currentStep == 2 -> {
                        val result = RustyCrypto.hybridSenderThird(keyData)
                        if (result == null || result.size != 2) {
                            withContext(Dispatchers.Main) {
                                showError("Failed to process 2.key bundle.")
                            }
                            return@launch
                        }
                        val package3 = result[0] as? ByteArray
                        val finalKey = result[1] as? ByteArray
                        if (package3 == null || finalKey == null || package3.isEmpty() || finalKey.isEmpty()) {
                            withContext(Dispatchers.Main) {
                                showError("Invalid data from native layer.")
                            }
                            return@launch
                        }
                        finalSharedSecret = finalKey
                        package3Bytes = package3
                        
                        withContext(Dispatchers.Main) {
                            queueSaveAndPersist("3.key", package3, "3.key generated - Share with receiver")
                            binding.tvStep1Result.text = "3.key generated - Auto-encrypting file..."
                            binding.tvStep1Result.visibility = View.VISIBLE
                            // Auto-encrypt file
                            performFileEncryption()
                        }
                    }
                    
                    // Receiver opening 3.key to finalize OR encrypted file to decrypt
                    !isSender && currentStep == 2 -> {
                        val name = getFileName(uri) ?: ""
                        if (name.endsWith(".key")) {
                            val finalKey: ByteArray? = RustyCrypto.hybridReceiverFinalDual(keyData)
                            if (finalKey == null || finalKey.isEmpty()) {
                                withContext(Dispatchers.Main) {
                                    showError("Failed to finalize with 3.key")
                                }
                                return@launch
                            }
                            finalSharedSecret = finalKey
                            withContext(Dispatchers.Main) {
                                binding.tvStep1Result.text = "Final key ready. Now open the encrypted file to decrypt."
                                binding.tvStep1Result.visibility = View.VISIBLE
                            }
                        } else {
                            // Perform decryption with the selected encrypted file
                            withContext(Dispatchers.Main) {
                                performFileDecryption(uri)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Error processing key: ${e.message}")
                }
            }
        }
    }

    private fun performFileEncryption() {
        if (selectedFileUri == null || finalSharedSecret == null) {
            showError("Missing file or encryption key")
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
                val inputPath = getRealPathFromUri(selectedFileUri!!)
                if (inputPath == null) {
                    withContext(Dispatchers.Main) {
                        showError("Cannot access selected file")
                    }
                    return@launch
                }

                // Use the selectedFilePath which contains the correct original filename
                val originalFileName = selectedFilePath
                val encryptedFileName = "${originalFileName}.pqrypt"
                
                val outputFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                
                val inputFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
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
                    val toSave = package3Bytes?.let { p3 ->
                        val combined = ByteArray(p3.size + encryptedBytes.size)
                        System.arraycopy(p3, 0, combined, 0, p3.size)
                        System.arraycopy(encryptedBytes, 0, combined, p3.size, encryptedBytes.size)
                        combined
                    } ?: encryptedBytes
                    withContext(Dispatchers.Main) {
                        queueSaveAndPersist(encryptedFileName, toSave, "File encrypted successfully!", showPathInResult = true)
                        currentStep = 4
                        updateUI()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        showError("File encryption failed")
                    }
                }
                
                outputFile.delete()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Encryption error: ${e.message}")
                }
            }
        }
    }

    private fun performFileDecryption(uri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                withContext(Dispatchers.Main) {
                    if (pickedFolderUri == null) {
                        binding.tvStatus.text = "Select destination folder before decryption"
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
                val inputPath = getRealPathFromUri(uri)
                if (inputPath == null) {
                    withContext(Dispatchers.Main) {
                        showError("Cannot access encrypted file")
                    }
                    return@launch
                }

                // Get the original filename from the URI instead of the temp file path
                val fileName = getFileName(uri) ?: "decrypted_file"
                val outputName = if (fileName.endsWith(".pqrypt")) {
                    fileName.removeSuffix(".pqrypt")
                } else {
                    fileName  // Keep original name without adding .decrypted
                }
                
                var decryptSourcePath = inputPath
                var tempToDelete: File? = null
                if (finalSharedSecret == null) {
                    val inputFile = File(inputPath)
                    if (inputFile.length() < P3_LEN + 73) {
                        withContext(Dispatchers.Main) { showError("Invalid encrypted file (too small for combined)") }
                        return@launch
                    }
                    // Assume combined file: read fixed-size 3.key prefix
                    val p3 = ByteArray(P3_LEN)
                    FileInputStream(inputFile).use { fis ->
                        var read = 0
                        while (read < P3_LEN) {
                            val r = fis.read(p3, read, P3_LEN - read)
                            if (r <= 0) break
                            read += r
                        }
                        if (read != P3_LEN) {
                            withContext(Dispatchers.Main) { showError("Failed to read embedded 3.key") }
                            return@launch
                        }
                    }
                    val fk = RustyCrypto.hybridReceiverFinalDual(p3)
                    if (fk == null || fk.isEmpty()) {
                        // Fallback: if file begins with header, then we truly have no key in memory
                        val first6 = ByteArray(6)
                        FileInputStream(inputFile).use { it.read(first6) }
                        val magic = byteArrayOf('P'.code.toByte(),'Q'.code.toByte(),'R'.code.toByte(),'Y'.code.toByte(),'P'.code.toByte(),'T'.code.toByte())
                        if (first6.contentEquals(magic)) {
                            withContext(Dispatchers.Main) { showError("No decryption key available. Please open 3.key first.") }
                        } else {
                            withContext(Dispatchers.Main) { showError("Failed to finalize with embedded 3.key") }
                        }
                        return@launch
                    }
                    finalSharedSecret = fk
                    // Trim prefix and continue decryption
                    val trimmed = File.createTempFile("trimmed_enc_", ".tmp", cacheDir)
                    FileInputStream(inputFile).use { fis ->
                        fis.skip(P3_LEN.toLong())
                        FileOutputStream(trimmed).use { fos ->
                            val buf = ByteArray(131072)
                            while (true) {
                                val r = fis.read(buf)
                                if (r <= 0) break
                                fos.write(buf, 0, r)
                            }
                            fos.flush()
                        }
                    }
                    decryptSourcePath = trimmed.absolutePath
                    tempToDelete = trimmed
                }

                val outputFile = File.createTempFile("decrypted_", ".tmp", cacheDir)
                val inputFd = ParcelFileDescriptor.open(File(decryptSourcePath), ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(outputFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)

                val success = try {
                    RustyCrypto.doubleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                if (success == RustyCrypto.CRYPTO_SUCCESS) {
                    val decryptedBytes = outputFile.readBytes()
                    withContext(Dispatchers.Main) {
                        queueSaveAndPersist(outputName, decryptedBytes, "File decrypted successfully!", showPathInResult = true)
                        currentStep = 4
                        updateUI()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        val errorMessage = when (success) {
                            RustyCrypto.CRYPTO_ERROR_DECRYPTION_FAILED -> "Authentication/decryption failed. This may be due to file corruption, tampering, or wrong file selection."
                            RustyCrypto.CRYPTO_ERROR_INVALID_INPUT -> "Invalid encrypted file. The file may be corrupted or not a valid encrypted file."
                            RustyCrypto.CRYPTO_ERROR_NULL_POINTER -> "File access error. Please check file permissions."
                            else -> "File decryption failed. This may be due to file corruption, tampering, or wrong file selection."
                        }
                        showError(errorMessage)
                    }
                }
                
                outputFile.delete()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Decryption error: ${e.message}")
                }
            }
        }
    }

    

    private fun openFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        filePickerLauncher.launch(intent)
    }

    private fun openKeyFile(expectedFile: String) {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        keyFilePickerLauncher.launch(intent)
    }

    private fun openEncryptedFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        keyFilePickerLauncher.launch(intent)
    }

    private fun resetStates() {
        // zeroize and clear in-memory secret
        finalSharedSecret?.fill(0)
        finalSharedSecret = null
    }

    // SAF functions copied from working PQC KeyExchangeProcessActivity
    private fun queueSaveAndPersist(filename: String, keyData: ByteArray, successMsg: String, showPathInResult: Boolean = false) {
        lifecycleScope.launch(Dispatchers.Main) {
            pendingOutputBytes = keyData
            pendingSuggestedName = filename
            pendingSuccessToast = successMsg
            pendingShowPathInResult = showPathInResult
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
        val showPath = pendingShowPathInResult
        if (folderUri == null || bytes == null || name.isNullOrEmpty()) return

        try {
            val outUri = createUniqueDocumentCopySuffix(folderUri, "application/octet-stream", name)
            if (outUri != null) {
                contentResolver.openOutputStream(outUri)?.use { it.write(bytes) }
                binding.tvStatus.text = pendingSuccessToast ?: "Saved"
                Toast.makeText(this, pendingSuccessToast ?: "Saved", Toast.LENGTH_SHORT).show()
                
                // Update result text with actual file path if requested
                if (showPath) {
                    val actualPath = getActualPathFromUri(outUri) ?: name
                    binding.tvStep1Result.text = "File saved: $actualPath"
                    binding.tvStep1Result.visibility = View.VISIBLE
                }
            } else {
                Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
        } finally {
            pendingOutputBytes = null
            pendingShowPathInResult = false
            pendingSuggestedName = null
            pendingSuccessToast = null
        }
    }

    private fun createUniqueDocumentCopySuffix(treeUri: Uri, mime: String, desiredName: String): Uri? {
        val treeDoc = DocumentFile.fromTreeUri(this, treeUri) ?: return null
        
        val existingFile = treeDoc.findFile(desiredName)
        if (existingFile != null && existingFile.exists()) {
            existingFile.delete()
        }

        val parentDocId = android.provider.DocumentsContract.getTreeDocumentId(treeUri)
        val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
        return android.provider.DocumentsContract.createDocument(contentResolver, parentDocUri, mime, desiredName)
    }

    private fun readFileBytes(uri: Uri): ByteArray? {
        return try {
            contentResolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (e: Exception) {
            null
        }
    }

    private fun getRealPathFromUri(uri: Uri): String? {
        return try {
            if (uri.scheme == "content") {
                val tempFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                tempFile.absolutePath
            } else {
                uri.path
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun getFileName(uri: Uri): String? {
        return contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex("_display_name")
            if (nameIndex >= 0 && cursor.moveToFirst()) {
                cursor.getString(nameIndex)
            } else null
        } ?: uri.lastPathSegment ?: "unknown"
    }
    
    private fun getActualPathFromUri(uri: Uri): String? {
        return try {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex("_display_name")
                if (nameIndex >= 0 && cursor.moveToFirst()) {
                    val fileName = cursor.getString(nameIndex)
                    // Try to get a readable path
                    val treeUri = pickedFolderUri
                    if (treeUri != null) {
                        val treePath = treeUri.path?.substringAfter(":")
                        if (treePath != null) {
                            "/storage/emulated/0/$treePath/$fileName"
                        } else {
                            fileName
                        }
                    } else {
                        fileName
                    }
                } else {
                    uri.lastPathSegment
                }
            }
        } catch (e: Exception) {
            uri.lastPathSegment
        }
    }

    private fun cleanupIntermediateFiles() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                var deletedCount = 0
                
                // Clean cache directory only
                cacheDir.listFiles()?.forEach { file ->
                    if (file.name.startsWith("encrypted_") ||
                        file.name.startsWith("decrypted_") ||
                        file.name.endsWith(".tmp")) {
                        if (file.delete()) deletedCount++
                    }
                }
                
                // Clean up key files in picked folder if available
                pickedFolderUri?.let { folderUri ->
                    val treeDoc = DocumentFile.fromTreeUri(this@SecureShareManualFileActivity, folderUri)
                    treeDoc?.listFiles()?.forEach { file ->
                        val name = file.name ?: ""
                        if (name.endsWith(".key") || name.endsWith(".pqrypt") || 
                            name.endsWith(".txt")) {
                            if (file.delete()) deletedCount++
                        }
                    }
                }
                
                resetStates()
                
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@SecureShareManualFileActivity, 
                        "Cleaned up $deletedCount files", 
                        Toast.LENGTH_SHORT).show()
                    binding.tvStatus.text = "Cleanup completed"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@SecureShareManualFileActivity, 
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
