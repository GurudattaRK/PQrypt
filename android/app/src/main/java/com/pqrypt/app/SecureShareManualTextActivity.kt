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
    
    // File and key management
    private var finalSharedSecret: ByteArray? = null
    private var lastOutputPath: String? = null
    private var etInputText: String = ""
    private var senderState: ByteArray? = null
    private var receiverState: ByteArray? = null
    
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
        binding.tvRole.text = "Role: ${role.replaceFirstChar { it.uppercase() }}"
        
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
                !isSender && currentStep == 2 -> openKeyFile("3.key")
                !isSender && currentStep == 3 -> openEncryptedTextFile()
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
            !isSender && currentStep == 2 -> "Open 3.key from Sender"
            !isSender && currentStep == 3 -> "Open Encrypted Text File"
            else -> "Process Complete"
        }
        
        binding.btnStep1.isEnabled = currentStep <= 3
        
        // Update status text
        binding.tvStatus.text = when {
            isSender && currentStep == 1 -> "Step 1: Enter your text message above, then press 'Generate 1.key' button"
            isSender && currentStep == 2 -> "Step 2: Send 1.key to receiver and wait for their 2.key. Once received, press 'Open 2.key from Receiver' button"
            isSender && currentStep > 2 -> "✅ Success! Your text has been encrypted. Send both 3.key and the encrypted text file to the receiver"
            !isSender && currentStep == 1 -> "Step 1: Wait for sender's 1.key file. Once received, press 'Open 1.key from Sender' button (2.key will auto-generate)"
            !isSender && currentStep == 2 -> "Step 2: Send 2.key to sender and wait for their 3.key. Once received, press 'Open 3.key from Sender' button"
            !isSender && currentStep == 3 -> "Step 3: Wait for encrypted text file from sender. Once received, press 'Open Encrypted Text File' button to decrypt"
            else -> "✅ Process complete! Message successfully decrypted"
        }
    }

    private fun generateStep1Key() {
        if (!isSender) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                resetStates()
                
                val result = RustyCrypto.pqc4HybridInit() as Array<*>
                val publicKey = result[0] as ByteArray
                senderState = result[1] as ByteArray
                
                withContext(Dispatchers.Main) {
                    saveKeyFile(publicKey, "1.key")
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
                    // Receiver opening 1.key -> auto-generate 2.key
                    !isSender && currentStep == 1 -> {
                        resetStates()
                        val recvResult = RustyCrypto.pqc4HybridRecv(keyData)
                        val response = recvResult[0] as ByteArray
                        receiverState = recvResult[1] as ByteArray
                        
                        withContext(Dispatchers.Main) {
                            if (response.isNotEmpty()) {
                                saveKeyFile(response, "2.key")
                                binding.tvStep1Result.text = "✅ 2.key generated automatically! Send this file to the sender"
                                binding.tvStep1Result.visibility = View.VISIBLE
                                currentStep = 2
                                updateUI()
                            } else {
                                showError("Failed to generate 2.key")
                            }
                        }
                    }
                    
                    // Sender opening 2.key -> auto-generate 3.key, final.key and encrypt text
                    isSender && currentStep == 2 -> {
                        if (senderState == null) {
                            withContext(Dispatchers.Main) {
                                showError("Sender state not initialized. Please restart from Step 1.")
                            }
                            return@launch
                        }
                        
                        val sndFinalResult = RustyCrypto.pqc4HybridSndFinal(keyData, senderState!!)
                        finalSharedSecret = sndFinalResult[0] as ByteArray
                        val result3Key = sndFinalResult[1] as ByteArray
                        
                        withContext(Dispatchers.Main) {
                            saveKeyFile(result3Key, "3.key")
                            saveKeyFile(finalSharedSecret!!, "final.key")
                            binding.tvStep1Result.text = "✅ 3.key and final.key generated! Encrypting your text message..."
                            binding.tvStep1Result.visibility = View.VISIBLE
                            
                            // Auto-encrypt text
                            performTextEncryption()
                        }
                    }
                    
                    // Receiver opening 3.key -> auto-generate final.key
                    !isSender && currentStep == 2 -> {
                        if (receiverState == null) {
                            withContext(Dispatchers.Main) {
                                showError("Receiver state not initialized. Please restart from Step 1.")
                            }
                            return@launch
                        }
                        
                        finalSharedSecret = RustyCrypto.pqc4HybridRecvFinal(keyData, receiverState!!)
                        
                        withContext(Dispatchers.Main) {
                            if (finalSharedSecret != null && finalSharedSecret!!.isNotEmpty()) {
                                saveKeyFile(finalSharedSecret!!, "final.key")
                                binding.tvStep1Result.text = "final.key auto-generated - Ready to decrypt"
                                binding.tvStep1Result.visibility = View.VISIBLE
                                currentStep = 3
                                updateUI()
                            } else {
                                showError("Failed to generate final key")
                            }
                        }
                    }
                    
                    // Receiver opening encrypted text -> auto-decrypt and display
                    !isSender && currentStep == 3 -> {
                        if (finalSharedSecret == null) {
                            withContext(Dispatchers.Main) {
                                showError("No decryption key available")
                            }
                            return@launch
                        }
                        
                        performTextDecryption(keyData)
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
        etInputText = binding.etTextInput.text.toString()
        if (finalSharedSecret == null || etInputText.trim().isEmpty()) {
            showError("Missing text or encryption key")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Create input file in cache
                val inputFile = File.createTempFile("input_", ".txt", cacheDir)
                inputFile.writeText(etInputText)
                
                // Create output file in cache
                val outputFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                
                val inputFd = ParcelFileDescriptor.open(inputFile, ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(outputFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val success = try {
                    RustyCrypto.tripleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                if (success == 0) {
                    val encryptedBytes = outputFile.readBytes()
                    
                    withContext(Dispatchers.Main) {
                        saveKeyFile(encryptedBytes, "text.encrypted")
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
                
                inputFile.delete()
                outputFile.delete()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Encryption error: ${e.message}")
                }
            }
        }
    }

    private fun performTextDecryption(encryptedData: ByteArray) {
        if (finalSharedSecret == null) {
            showError("No decryption key available")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Write encrypted data to temp file
                val inputFile = File.createTempFile("encrypted_", ".tmp", cacheDir)
                inputFile.writeBytes(encryptedData)
                
                val outputFile = File.createTempFile("decrypted_", ".txt", cacheDir)
                
                val inputFd = ParcelFileDescriptor.open(inputFile, ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(outputFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val success = try {
                    RustyCrypto.tripleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                if (success == 0) {
                    val decryptedBytes = outputFile.readBytes()
                    val decryptedText = String(decryptedBytes)
                    
                    withContext(Dispatchers.Main) {
                        // Display decrypted text
                        binding.tvDecryptedText.text = decryptedText
                        binding.tvStep1Result.text = "Text decrypted successfully!"
                        binding.tvStep1Result.visibility = View.VISIBLE
                        
                        // Also save to file
                        saveKeyFile(decryptedBytes, "text_decrypted.txt")
                        currentStep = 4
                        updateUI()
                    }
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
        senderState = null
        receiverState = null
        finalSharedSecret = null
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
