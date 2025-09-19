package com.pqrypt.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
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
import java.io.File
import java.io.FileWriter

class SecureShareManualTextActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareManualTextBinding
    private var contentType = "text"
    private var transferMode = "manual"
    private var role = "sender"
    private var isSender = true
    private var currentStep = 1
    
    // File and key management
    private var selectedFileUri: Uri? = null
    private var selectedFilePath = ""
    private var pickedFolderUri: Uri? = null
    private var finalSharedSecret: ByteArray? = null
    private var tempTextFile: File? = null
    private var lastOutputPath: String? = null
    private var etInputText: String = ""
    private var senderState: Any? = null
    private var receiverState: Any? = null

    private val keyFilePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                handleKeyFileSelection(uri)
            }
        }
    }

    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val treeUri = result.data?.data
            if (treeUri != null) {
                pickedFolderUri = treeUri
                binding.tvOutputFolder.text = "Output folder: ${getDisplayPath(treeUri)}"
                // Persist permissions
                try {
                    val flags = result.data?.flags ?: 0
                    contentResolver.takePersistableUriPermission(
                        treeUri, 
                        flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                    )
                } catch (_: Exception) {}
            }
        }
    }

    private val encryptedTextFilePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                handleEncryptedTextFileSelection(uri)
            }
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

        setupUI()
        updateUI()
    }

    private fun setupUI() {
        binding.tvRole.text = "Role: ${role.capitalize()}"
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "secure_share"))
        }

        // Text input character counter
        binding.etTextInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                etInputText = s?.toString() ?: ""
                binding.tvCharCount.text = "${etInputText.length} characters"
                updateUI()
                
                // Auto-generate keys when text is entered (for sender)
                if (isSender && etInputText.isNotEmpty() && currentStep == 1) {
                    autoGenerateInitialKeys()
                }
            }
        })

        // Output folder selection
        binding.btnChooseOutputFolder.setOnClickListener {
            openFolderPicker()
        }

        // Step buttons
        binding.btnStep1.setOnClickListener {
            performStep1()
        }

        binding.btnStep2.setOnClickListener {
            openKeyFilePicker()
        }

        binding.btnStep3.setOnClickListener {
            openKeyFilePicker()
        }

        binding.btnStep4.setOnClickListener {
            if (isSender) {
                // Sender: auto-encrypt text after final key generation
                performTextEncryption()
            } else {
                // Receiver: choose encrypted text file to decrypt
                openEncryptedTextFilePicker()
            }
        }
    }

    private fun updateUI() {
        // Show/hide UI elements based on role
        binding.llTextInput.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.llTextDisplay.visibility = if (!isSender) View.VISIBLE else View.GONE
        
        // Update step button texts based on role
        if (isSender) {
            binding.btnStep2.text = "Step 2: Open 2.key & Auto-Generate 3.key"
            binding.btnStep4.text = "Step 4: Encrypt & Share Text"
        } else {
            binding.btnStep2.text = "Step 2: Open 1.key & Auto-Generate 2.key"  
            binding.btnStep3.text = "Step 3: Open 3.key & Auto-Generate final.key"
            binding.btnStep4.text = "Step 4: Choose Encrypted Text File & Auto-Decrypt"
        }

        // Enable/disable buttons based on current step and role
        binding.btnStep1.isEnabled = currentStep == 1
        binding.btnStep2.isEnabled = currentStep == 2
        binding.btnStep3.isEnabled = currentStep == 3
        binding.btnStep4.isEnabled = currentStep == 4

        // For sender, require text input before step 1
        if (isSender && currentStep == 1) {
            binding.btnStep1.isEnabled = etInputText.trim().isNotEmpty()
        }
    }

    private fun autoGenerateInitialKeys() {
        if (currentStep != 1 || !isSender) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Create temporary text file
                createTempTextFile()
                
                // Generate initial key
                val result = RustyCrypto.pqc4HybridInit()
                
                withContext(Dispatchers.Main) {
                    if (result != null && result.isNotEmpty()) {
                        binding.tvStatus.text = "Keys auto-generated. Ready for step 1."
                        // Enable step 1 button
                        updateUI()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Auto key generation failed: ${e.message}")
                }
            }
        }
    }

    private fun performStep1() {
        if (isSender && etInputText.trim().isEmpty()) {
            showError("Please enter text to share")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Create text file for sender
                if (isSender) {
                    createTempTextFile()
                }

                // Generate initial key (1.key for sender)
                val result = if (isSender) {
                    val initResult = RustyCrypto.pqc4HybridInit()
                    senderState = initResult[1] as ByteArray
                    initResult[0] as ByteArray
                } else {
                    // Receiver doesn't do step 1, this shouldn't happen
                    return@launch
                }

                withContext(Dispatchers.Main) {
                    if (result != null && result.isNotEmpty()) {
                        // Save the key file
                        saveKeyFile(result, "1.key")
                        binding.tvStep1Result.text = "Generated 1.key - Share with receiver"
                        binding.tvStep1Result.visibility = View.VISIBLE
                        currentStep = 2
                        updateUI()
                    } else {
                        showError("Failed to generate initial key")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Error generating key: ${e.message}")
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

                val result = when (currentStep) {
                    2 -> {
                        if (isSender) {
                            // Sender opening 2.key, generate 3.key
                            val sndFinalResult = RustyCrypto.pqc4HybridSndFinal(keyData, senderState as ByteArray)
                            finalSharedSecret = sndFinalResult[0] as ByteArray
                            sndFinalResult[1] as ByteArray
                        } else {
                            // Receiver opening 1.key, generate 2.key
                            val recvResult = RustyCrypto.pqc4HybridRecv(keyData)
                            receiverState = recvResult[1] as ByteArray
                            recvResult[0] as ByteArray
                        }
                    }
                    3 -> {
                        if (!isSender) {
                            // Receiver opening 3.key, generate final.key
                            RustyCrypto.pqc4HybridRecvFinal(keyData, receiverState as ByteArray)
                        } else null
                    }
                    else -> null
                }

                withContext(Dispatchers.Main) {
                    if (result != null && result.isNotEmpty()) {
                        val fileName = when (currentStep) {
                            2 -> if (isSender) "3.key" else "2.key"
                            3 -> "final.key"
                            else -> "key.key"
                        }
                        
                        saveKeyFile(result, fileName)
                        
                        val message = when (currentStep) {
                            2 -> if (isSender) "Generated 3.key - Share with receiver" else "Generated 2.key - Share with sender"
                            3 -> "Generated final.key - Ready for text operations"
                            else -> "Key generated"
                        }
                        
                        when (currentStep) {
                            2 -> {
                                binding.tvStep2Result.text = message
                                binding.tvStep2Result.visibility = View.VISIBLE
                            }
                            3 -> {
                                binding.tvStep3Result.text = message
                                binding.tvStep3Result.visibility = View.VISIBLE
                                finalSharedSecret = result
                            }
                        }
                        
                        currentStep++
                        updateUI()
                        
                        // Auto-encrypt for sender when final key is generated
                        if (isSender && currentStep == 4) {
                            performTextEncryption()
                        }
                    } else {
                        showError("Failed to process key file")
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
        if (tempTextFile == null || finalSharedSecret == null || etInputText.trim().isEmpty()) {
            showError("Missing text or encryption key")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Update text file with current input
                createTempTextFile()
                
                val inputPath = tempTextFile!!.absolutePath
                val outputPath = "${inputPath}.secure_share.pqrypt2"
                
                // Open file descriptors for real encryption
                val inputFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(File(outputPath), ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val success = try {
                    // Use real triple encryption with the shared secret
                    RustyCrypto.tripleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1 // failure
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                withContext(Dispatchers.Main) {
                    if (success == 0) {
                        lastOutputPath = outputPath
                        binding.tvStep4Result.text = "Text encrypted: ${File(outputPath).name}\nLocation: $outputPath"
                        binding.tvStep4Result.visibility = View.VISIBLE
                        showSuccess("Text encrypted successfully! Share the encrypted file.")
                    } else {
                        showError("Text encryption failed")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Encryption error: ${e.message}")
                }
            }
        }
    }

    private fun handleEncryptedTextFileSelection(uri: Uri) {
        if (finalSharedSecret == null) {
            showError("Final key not generated yet")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val inputPath = getRealPathFromUri(uri)
                if (inputPath == null) {
                    withContext(Dispatchers.Main) {
                        showError("Cannot access encrypted file")
                    }
                    return@launch
                }

                val fileName = File(inputPath).name
                val outputName = if (fileName.endsWith(".secure_share.pqrypt2")) {
                    fileName.removeSuffix(".secure_share.pqrypt2")
                } else if (fileName.endsWith(".pqrypt2")) {
                    fileName.removeSuffix(".pqrypt2")
                } else {
                    "${fileName}.decrypted"
                }

                val outputPath = "${File(inputPath).parent}/${outputName}"
                
                // Open file descriptors for real decryption
                val inputFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
                val outputFd = ParcelFileDescriptor.open(File(outputPath), ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
                
                val success = try {
                    // Use real triple decryption with the shared secret
                    RustyCrypto.tripleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                } catch (e: Exception) {
                    -1 // failure
                } finally {
                    inputFd.close()
                    outputFd.close()
                }

                withContext(Dispatchers.Main) {
                    if (success == 0) {
                        // Read decrypted text and display it
                        val decryptedText = File(outputPath).readText()
                        binding.tvDecryptedText.text = decryptedText
                        lastOutputPath = outputPath
                        binding.tvStep4Result.text = "Text decrypted successfully\nLocation: $outputPath"
                        binding.tvStep4Result.visibility = View.VISIBLE
                        showSuccess("Text decrypted and displayed!")
                    } else {
                        showError("Text decryption failed")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Decryption error: ${e.message}")
                }
            }
        }
    }

    private fun createTempTextFile() {
        try {
            tempTextFile = File.createTempFile("secure_share_text", ".txt", cacheDir)
            FileWriter(tempTextFile!!).use { writer ->
                writer.write(etInputText)
            }
        } catch (e: Exception) {
            showError("Failed to create temporary text file: ${e.message}")
        }
    }

    private fun openKeyFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        keyFilePickerLauncher.launch(intent)
    }

    private fun openEncryptedTextFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        encryptedTextFilePickerLauncher.launch(intent)
    }

    private fun openFolderPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        folderPickerLauncher.launch(intent)
    }

    private fun saveKeyFile(keyData: ByteArray, fileName: String) {
        // Implementation to save key file using SAF
        // This would use the picked folder or default downloads folder
    }

    private fun readFileBytes(uri: Uri): ByteArray? {
        return try {
            contentResolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (e: Exception) {
            null
        }
    }

    private fun getRealPathFromUri(uri: Uri): String? {
        // Implementation to get real file path from URI
        // This may require copying to cache for some URIs
        return null // Placeholder
    }

    private fun getDisplayPath(uri: Uri): String {
        return uri.path ?: "Selected folder"
    }

    private fun showError(message: String) {
        binding.tvStatus.text = "Error: $message"
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun showSuccess(message: String) {
        binding.tvStatus.text = message
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Clean up temporary text file
        tempTextFile?.delete()
    }
}
