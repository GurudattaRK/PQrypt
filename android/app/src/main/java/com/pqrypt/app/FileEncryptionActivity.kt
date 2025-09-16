package com.pqrypt.app // Package namespace for this Kotlin file

import android.app.Activity // For activity result status codes
import android.content.Intent // To launch pickers and SAF actions
import android.net.Uri // To reference selected files and tree URIs
import android.os.Bundle // Activity lifecycle state container
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract // SAF contract constants/utilities
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity // Base class for activities with support features
import androidx.lifecycle.lifecycleScope
import androidx.documentfile.provider.DocumentFile // SAF-friendly file/folder abstraction
import com.pqrypt.app.databinding.ActivityFileEncryptionBinding // ViewBinding for activity_file_encryption.xml
import kotlinx.coroutines.CoroutineScope // Coroutines for async work and debouncing
import kotlinx.coroutines.Dispatchers // Coroutines for async work and debouncing
import kotlinx.coroutines.Job // Coroutines job management
import kotlinx.coroutines.delay // Coroutines delay function
import kotlinx.coroutines.launch // Coroutines for async work and debouncing
import kotlinx.coroutines.withContext // Coroutines for async work and debouncing
import java.io.File // File path helper (may be used when resolving names)
import java.io.ByteArrayOutputStream // Stream for assembling output bytes
import java.io.FileOutputStream // Stream for writing local files
import java.security.SecureRandom // CSPRNG if needed for salts/keys
import android.text.TextWatcher // Listen to password field changes
import android.text.Editable // Editable text passed to TextWatcher
import javax.crypto.Mac // HMAC used in HKDF operations
import javax.crypto.spec.SecretKeySpec // Key wrapper for MAC

class FileEncryptionActivity : AppCompatActivity() { // UI for selecting files and encrypting/decrypting them

    private lateinit var binding: ActivityFileEncryptionBinding // Late-init view binding for this layout
    private var selectedFileUri: Uri? = null // Currently chosen input file URI
    private var selectedFilePath: String = "" // Display name/path for UI feedback
    private var passwordKey: ByteArray? = null // Derived 128-byte key for crypto operations
    private var currentSalt: ByteArray? = null // Placeholder for salt if/when used
    // Key-file flow state
    private var isUsingKeyFile: Boolean = false // Whether key-file mode is active instead of password text
    private var selectedKeyFileUri: Uri? = null // Chosen key file URI
    private var keyFileFirst128: ByteArray? = null // Cached bytes from key file used for derivation
    // Pending output when using the SAF create-document flow
    private var pendingOutputBytes: ByteArray? = null // Stash encrypted data for saving
    private var pendingSuggestedName: String? = null // Stash filename suggestion
    private var pendingSuccessToast: String? = null // Stash success message
    private var pendingEncryptionSecret: ByteArray? = null // Secret for streaming encryption
    private var pendingDecryptionSecret: ByteArray? = null // Secret for streaming decryption to show after successful save
    // Persisted target folder (tree URI) for Option B
    private var pickedFolderUri: Uri? = null // Persisted user-selected output folder URI
    private var pendingAction: String? = null // "encrypt" or "decrypt" action to run after picking folder

    private val filePickerLauncher = registerForActivityResult( // Launcher for picking input file via SAF
        ActivityResultContracts.StartActivityForResult()
    ) { result -> // Handle picker result
        if (result.resultCode == Activity.RESULT_OK) { // Proceed only if user confirmed selection
            result.data?.data?.let { uri -> // Extract the returned content URI
                selectedFileUri = uri // Remember chosen file
                selectedFilePath = getFileName(uri) // Resolve display name for UI
                val fullPath = getFullPath(uri) // Best-effort readable path for display
                binding.tvSelectedFile.text = "Selected: $fullPath" // Show selection
                updateButtonStates() // Enable/disable buttons accordingly
            }
        }
    }

    private val keyFilePickerLauncher = registerForActivityResult( // Launcher for selecting a key file source
        ActivityResultContracts.StartActivityForResult()
    ) { result -> // Handle key file selection
        if (result.resultCode == Activity.RESULT_OK) { // Only proceed on confirmation
            result.data?.data?.let { uri -> // Extract selected key file URI
                // Read at most 128 bytes from selected key file
                try {
                    // Read entire file and require a minimum of 8 bytes
                    val allBytes = readAllBytes(uri) // Load key material bytes
                    if (allBytes == null) { // Error/empty read
                        Toast.makeText(this, "Failed to read key file or the chosen file has zero bytes", Toast.LENGTH_SHORT).show()
                        return@let // Abort
                    }
                    if (allBytes.size < 8) { // Enforce minimal entropy/length
                        Toast.makeText(this, "Key file must have at least 8 bytes", Toast.LENGTH_SHORT).show()
                        return@let // Abort
                    }
                    selectedKeyFileUri = uri // Remember the key file URI
                    // Store only first 128 bytes for streaming API compatibility
                    keyFileFirst128 = allBytes.take(128).toByteArray() // Cache first 128 bytes for derivation
                    isUsingKeyFile = true // Switch UI/logic into key-file mode
                    // Derive a session key to enable buttons (real derivation done again with fresh salt per op)
                    deriveKeyFromKeyFilePreview() // Perform preview derivation to enable actions
                    // Update UI to reflect key-file usage
                    binding.etPassword.setText("") // Clear password field
                    binding.etPassword.isEnabled = false // Disable password input while in key-file mode
                    val path = getFullPath(uri) // Resolve human-readable path
                    binding.tvKeyFilePath.text = "Key file: $path" // Show key file used
                    Toast.makeText(this, "Key file selected: ${getFileName(uri)}", Toast.LENGTH_SHORT).show() // Confirmation toast
                } catch (e: Exception) {
                    Toast.makeText(this, "Key file error: ${e.message}", Toast.LENGTH_SHORT).show() // Report error
                }
            }
        }
    }

    private val pickFolderLauncher = registerForActivityResult( // Launcher to pick target output folder (tree URI)
        ActivityResultContracts.StartActivityForResult()
    ) { result -> // Handle folder picker result
        if (result.resultCode == Activity.RESULT_OK) { // Proceed only if user chose a folder
            val treeUri = result.data?.data // Returned tree URI representing the folder
            if (treeUri != null) {
                // Persist permissions
                val flags = result.data?.flags ?: 0 // Inherit granted flags
                try {
                    contentResolver.takePersistableUriPermission(
                        treeUri, // Target folder URI
                        (flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)) // Persist R/W
                    )
                } catch (_: Exception) {}

                pickedFolderUri = treeUri // Remember folder for subsequent operations
                getSharedPreferences("pqrypt_prefs", MODE_PRIVATE)
                    .edit().putString("picked_folder_uri", treeUri.toString()).apply() // Persist across restarts

                // Start the pending action now that a folder is selected
                when (pendingAction) { // Resume flow based on pending action
                    "encrypt" -> {
                        pendingAction = null // Clear pending marker
                        val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "file"
                        val outputFileName = "${inputFileName}.pqrypt2"
                        binding.tvOutputPath.text = "Encrypting...." // Show actual output filename
                        Toast.makeText(this, "Encryption started", Toast.LENGTH_SHORT).show() // Notify user
                        performEncryption() // Continue with encryption
                    }
                    "decrypt" -> {
                        pendingAction = null // Clear pending marker
                        val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "file"
                        val outputFileName = if (inputFileName.endsWith(".pqrypt2")) {
                            inputFileName.removeSuffix(".pqrypt2")
                        } else {
                            "${inputFileName}.decrypted"
                        }
                        binding.tvOutputPath.text = "Decrypting...." // Show actual output filename
                        Toast.makeText(this, "Decryption started", Toast.LENGTH_SHORT).show() // Notify user
                        performDecryption() // Continue with decryption
                    }
                    else -> { /* no-op */ } // Nothing to resume
                }
            }
        } else {
            Toast.makeText(this, "Folder selection cancelled", Toast.LENGTH_SHORT).show() // Inform user on cancel
        }
    }

    private val createDocumentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val outUri = result.data?.data
            if (outUri != null && pendingOutputBytes != null) {
                try {
                    contentResolver.openOutputStream(outUri)?.use { it.write(pendingOutputBytes) }
                    // Extract timing from success toast and add to path display
                    val timingInfo = pendingSuccessToast?.substringBefore(" (") ?: ""
                    val timingPart = if (timingInfo.contains("in ")) timingInfo.substringAfter("in ") else ""
                    binding.tvOutputPath.text = if (timingPart.isNotEmpty()) {
                        "⏱️ $timingPart - Saved to: ${getFullPath(outUri)}"
                    } else {
                        "Saved to: ${getFullPath(outUri)}"
                    }
                    Toast.makeText(this, pendingSuccessToast ?: "Saved", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
                } finally {
                    pendingOutputBytes = null
                    pendingSuggestedName = null
                    pendingSuccessToast = null
                }
            } else {
                Toast.makeText(this, "Nothing to save", Toast.LENGTH_SHORT).show()
            }
        } else {
            // User cancelled save dialog
            pendingOutputBytes = null
            pendingSuggestedName = null
            pendingSuccessToast = null
            Toast.makeText(this, "Save cancelled", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileEncryptionBinding.inflate(layoutInflater) // Inflate view binding for this screen
        setContentView(binding.root) // Attach inflated layout to the activity

        // Load persisted folder if available
        val saved = getSharedPreferences("pqrypt_prefs", MODE_PRIVATE).getString("picked_folder_uri", null) // Retrieve stored tree URI
        if (!saved.isNullOrEmpty()) { // If a folder was previously chosen and persisted
            pickedFolderUri = Uri.parse(saved) // Restore it for immediate use
        }

        setupUI() // Wire up listeners and initialize UI state
    }

    private fun setupUI() { // Set up all UI event handlers and state synchronization
        binding.btnBack.setOnClickListener { // Navigate back to previous screen
            finish() // Close this activity
        }

        binding.btnHelp.setOnClickListener { // Open help screen
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "file_encryption"))
        }

        binding.btnChooseFile.setOnClickListener { // Choose input file via SAF
            openFilePicker() // Launch the file picker
        }

        binding.btnUseKeyFile.setOnClickListener { // Select an external key file to derive key from
            openKeyFilePicker() // Launch the key-file picker
        }

        binding.etPassword.setOnFocusChangeListener { _, hasFocus -> // When password field loses focus
            if (!hasFocus && binding.etPassword.text.isNotEmpty()) { // If there is input present
                generatePasswordKey() // Derive the password key
            }
        }

        // Also generate key when user types (with debouncing)
        binding.etPassword.addTextChangedListener(object : TextWatcher { // Watch text input to trigger derivation
            private var textChangeJob: Job? = null // Debounce job to avoid deriving on every keystroke

            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {} // No-op
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {} // No-op

            override fun afterTextChanged(s: Editable?) { // Debounced key derivation after user pauses typing
                textChangeJob?.cancel() // Cancel any pending job
                if (s?.isNotEmpty() == true) { // If there is some input
                    // Switch back to password mode if user types
                    if (isUsingKeyFile) { // If previously using key-file mode, revert to password mode
                        isUsingKeyFile = false // Disable key-file mode
                        selectedKeyFileUri = null // Clear chosen key file
                        keyFileFirst128 = null // Clear cached key bytes
                        binding.etPassword.isEnabled = true // Re-enable password field
                        binding.tvKeyFilePath.text = "Key file: None" // Reflect state in UI
                    }
                    textChangeJob = CoroutineScope(Dispatchers.Main).launch { // Schedule derivation after delay
                        delay(1000) // Wait 1 second after user stops typing
                        if (binding.etPassword.text.toString() == s.toString()) { // Ensure text hasn't changed again
                            generatePasswordKey() // Derive key from current text
                        }
                    }
                } else {
                    // No password text; if not using key file, clear key
                    if (!isUsingKeyFile) { // Only clear when in password mode
                        passwordKey = null // Remove derived key
                        updateButtonStates() // Disable encrypt/decrypt buttons accordingly
                    }
                }
            }
        })

        binding.btnEncrypt.setOnClickListener { // Handle encrypt button press

            // Ensure password key is generated before encryption
            if (selectedFileUri != null) { // Proceed only if an input file has been chosen
                if (passwordKey == null && (binding.etPassword.text.isNotEmpty() || isUsingKeyFile)) { // Key missing but inputs present
                    if (isUsingKeyFile) deriveKeyFromKeyFilePreview() else generatePasswordKey() // Choose derivation source
                    // Wait a moment for key generation, then try again
                    CoroutineScope(Dispatchers.Main).launch { // Delay to allow async derivation to complete
                        delay(500)
                        if (passwordKey != null) { // If key now available
                            if (pickedFolderUri == null) { // Ensure we have an output folder
                                pendingAction = "encrypt" // Remember desired action
                                launchPickFolder() // Ask user to choose folder
                            } else {
                                val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "file"
                                val outputFileName = "${inputFileName}.pqrypt2"
                                binding.tvOutputPath.text = "Started processing your file, please wait...." // Show processing status
                                Toast.makeText(this@FileEncryptionActivity, "Encryption started", Toast.LENGTH_SHORT).show() // UX feedback
                                performEncryption() // Begin encryption workflow
                            }
                        } else { // Derivation still not ready/failed
                            Toast.makeText(this@FileEncryptionActivity, "Please wait for password key generation to complete", Toast.LENGTH_SHORT).show() // Notify user
                        }
                    }
                } else if (passwordKey != null) { // If key already present
                    if (pickedFolderUri == null) {
                        pendingAction = "encrypt"
                        launchPickFolder()
                    } else {
                        val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "file"
                        val outputFileName = "${inputFileName}.pqrypt2"
                        binding.tvOutputPath.text = "Started processing your file, please wait...."
                        Toast.makeText(this, "Encryption started", Toast.LENGTH_SHORT).show()
                        performEncryption()
                    }
                } else {
                    Toast.makeText(this, if (isUsingKeyFile) "Please select files" else "Please select a file and enter password", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(this, "Please select a file first", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnDecrypt.setOnClickListener { // Handle decrypt button press

            // Ensure password key is generated before decryption
            if (selectedFileUri != null) { // Proceed only if an input file has been chosen
                if (passwordKey == null && binding.etPassword.text.isNotEmpty()) { // Key missing but password entered
                    generatePasswordKey() // Derive from entered password
                    // Wait a moment for key generation, then try again
                    CoroutineScope(Dispatchers.Main).launch { // Delay to allow async derivation to complete
                        delay(500)
                        if (passwordKey != null) { // If key now available
                            if (pickedFolderUri == null) { // Ensure we have an output folder
                                pendingAction = "decrypt" // Remember desired action
                                launchPickFolder() // Ask user to choose folder
                            } else {
                                val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "file"
                                val outputFileName = if (inputFileName.endsWith(".pqrypt2")) {
                                    inputFileName.removeSuffix(".pqrypt2")
                                } else {
                                    "${inputFileName}.decrypted"
                                }
                                binding.tvOutputPath.text = "Started processing your file, please wait...." // Show processing status
                                Toast.makeText(this@FileEncryptionActivity, "Decryption started", Toast.LENGTH_SHORT).show() // UX feedback
                                performDecryption() // Begin decryption workflow
                            }
                        } else { // Derivation still not ready/failed
                            Toast.makeText(this@FileEncryptionActivity, "Please wait for password key generation to complete", Toast.LENGTH_SHORT).show() // Notify user
                        }
                    }
                } else if (passwordKey != null) { // If key already present
                    if (pickedFolderUri == null) { // Ensure we have an output folder
                        pendingAction = "decrypt" // Remember desired action
                        launchPickFolder() // Ask user to choose folder
                    } else {
                        binding.tvOutputPath.text = "Processing your file please wait...." // Inform user
                        Toast.makeText(this, "Decryption started", Toast.LENGTH_SHORT).show() // UX feedback
                        performDecryption() // Start decryption
                    }
                } else { // No password provided
 // Log issue
                    Toast.makeText(this, "Please select a file and enter password", Toast.LENGTH_SHORT).show() // Prompt user
                }
            } else { // No file chosen
 // Log issue
                Toast.makeText(this, "Please select a file first", Toast.LENGTH_SHORT).show() // Prompt user
            }
        }

        // Initially disable encrypt/decrypt buttons
        updateButtonStates()
    }

    private fun openFilePicker() { // Launch the SAF to pick an input file
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply { // Create a get-content intent
            type = "*/*" // Allow any mime type
            addCategory(Intent.CATEGORY_OPENABLE) // Restrict to openable URIs (files)
        }
        filePickerLauncher.launch(intent) // Start picker
    }

    private fun openKeyFilePicker() { // Launch the SAF to pick a key file
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply { // Create a get-content intent
            type = "*/*" // Allow any mime type
            addCategory(Intent.CATEGORY_OPENABLE) // Restrict to openable URIs (files)
        }
        keyFilePickerLauncher.launch(intent) // Start picker
    }

    private fun generatePasswordKey() { // Derive a 128-byte key from the entered password using Argon2 (no salt)
        val password = binding.etPassword.text.toString() // Read text from input field
        if (password.isNotEmpty()) { // Only derive when non-empty
            CoroutineScope(Dispatchers.IO).launch { // Work off the main thread
                try {
                    // Argon2-only 128B with NO SALT (deterministic across platforms)
                    val salt = ByteArray(0) // Empty salt for deterministic behavior
                    val argonOut = RustyCrypto.argon2Hash( // Call into native to derive bytes
                        password.toByteArray(),
                        salt,
                        128
                    )
                    if (argonOut == null || argonOut.size != 128) { // Validate output length
                        withContext(Dispatchers.Main) {
                            passwordKey = null // Clear on failure
                            updateButtonStates() // Reflect disabled actions
                            Toast.makeText(this@FileEncryptionActivity, "Key derivation failed: Argon2(128) output invalid", Toast.LENGTH_LONG).show() // Inform user
                        }
                        return@launch // Abort
                    }
                    passwordKey = argonOut // Store derived key

                    withContext(Dispatchers.Main) { // Back to UI thread
                        updateButtonStates() // Enable actions
                        Toast.makeText(this@FileEncryptionActivity, "Password key generated", Toast.LENGTH_SHORT).show() // Confirm
                    }
                } catch (e: Exception) { // Handle derivation errors
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@FileEncryptionActivity, "Error generating key: ${e.message}", Toast.LENGTH_SHORT).show() // Report
                    }
                }
            }
        }
    }

    private fun deriveKeyFromKeyFilePreview() { // Derive a usable session key from the selected key file (no salt)
        val keySrc = keyFileFirst128 ?: return // Abort if no key bytes cached
        CoroutineScope(Dispatchers.IO).launch { // Work off the main thread
            try {
                // Argon2-only 128B with NO SALT (deterministic across platforms)
                val salt = ByteArray(0) // Empty salt for deterministic behavior
                val argonOut = RustyCrypto.argon2Hash(keySrc, salt, 128) // Derive 128 bytes from key file material
                if (argonOut == null || argonOut.size != 128) { // Validate output
                    withContext(Dispatchers.Main) {
                        passwordKey = null // Clear on failure
                        updateButtonStates() // Reflect disabled actions
                        Toast.makeText(this@FileEncryptionActivity, "Key derivation failed (key file)", Toast.LENGTH_LONG).show() // Inform user
                    }
                    return@launch // Abort
                }
                // HKDF-expand the Argon2 output to a final 128-byte master key
                val expanded = hkdfSha256Expand(prk = hkdfExtract(salt, argonOut), info = "PQryptMasterKey".toByteArray(), length = 128)
                if (expanded.size != 128) { // Validate expanded length
                    withContext(Dispatchers.Main) {
                        passwordKey = null // Clear on failure
                        updateButtonStates() // Reflect disabled actions
                        Toast.makeText(this@FileEncryptionActivity, "HKDF expand failed (key file)", Toast.LENGTH_LONG).show() // Inform user
                    }
                    return@launch // Abort
                }
                passwordKey = expanded // Store final key
                withContext(Dispatchers.Main) { updateButtonStates() } // Update UI
            } catch (e: Exception) { // Handle derivation errors
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileEncryptionActivity, "Key file error: ${e.message}", Toast.LENGTH_SHORT).show() // Report
                }
            }
        }
    }

    private fun performEncryption() {
        CoroutineScope(Dispatchers.IO).launch {
            val startTime = System.currentTimeMillis()
            try {
                
                // Derive secret from password or key file
                val secret = if (isUsingKeyFile) {
                    val keyBytes = keyFileFirst128 ?: throw IllegalStateException("No key file bytes available")
                    // Ensure we only use first 128 bytes for streaming API compatibility
                    if (keyBytes.size > 128) keyBytes.take(128).toByteArray() else keyBytes
                } else {
                    val derivedKey = passwordKey ?: throw IllegalStateException("No password key available")
                    derivedKey
                }
                
                // Get input file name for output suggestion
                val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "encrypted_file"
                val suggestedName = "${inputFileName}.pqrypt2"
                
                withContext(Dispatchers.Main) {
                    // Store encryption parameters for save flow
                    pendingEncryptionSecret = secret
                    pendingSuggestedName = suggestedName
                    pendingSuccessToast = "File encrypted in streaming mode"
                    
                    // Try to save to same location as input file first
                    val inputParentUri = getParentDirectoryUri(selectedFileUri!!)
                    if (inputParentUri != null) {
                        saveEncryptedToSameLocation(inputParentUri, suggestedName)
                    } else if (pickedFolderUri != null) {
                        saveEncryptedToPickedFolder()
                    } else {
                        launchPickFolderForEncryption()
                    }
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileEncryptionActivity, "Encryption error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun performDecryption() {
        CoroutineScope(Dispatchers.IO).launch {
            val startTime = System.currentTimeMillis()
            try {
                
                // Derive secret from password or key file
                val secret = if (isUsingKeyFile) {
                    val keyBytes = keyFileFirst128 ?: throw IllegalStateException("No key file bytes available")
                    // Ensure we only use first 128 bytes for streaming API compatibility
                    if (keyBytes.size > 128) keyBytes.take(128).toByteArray() else keyBytes
                } else {
                    val derivedKey = passwordKey ?: throw IllegalStateException("No password key available")
                    derivedKey
                }
                
                // Get input file name for output suggestion
                val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "decrypted_file"
                val suggestedName = if (inputFileName.endsWith(".pqrypt2")) {
                    inputFileName.removeSuffix(".pqrypt2")
                } else {
                    "${inputFileName}.decrypted"
                }
                
                withContext(Dispatchers.Main) {
                    // Store decryption parameters for save flow
                    pendingDecryptionSecret = secret
                    pendingSuggestedName = suggestedName
                    pendingSuccessToast = "File decrypted in streaming mode"
                    
                    // Try to save to same location as input file first
                    val inputParentUri = getParentDirectoryUri(selectedFileUri!!)
                    if (inputParentUri != null) {
                        saveDecryptedToSameLocation(inputParentUri, suggestedName)
                    } else if (pickedFolderUri != null) {
                        saveDecryptedToPickedFolder()
                    } else {
                        launchPickFolderForDecryption()
                    }
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMessage = if (e.message?.contains("Authentication/decryption failed") == true || 
                                           e.message?.contains("tampering") == true) {
                        e.message
                    } else {
                        "Decryption error: ${e.message}"
                    }
                    Toast.makeText(this@FileEncryptionActivity, errorMessage, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // New FD-based streaming functions
    private fun launchPickFolderForEncryption() {
        pendingAction = "encrypt"
        launchPickFolder()
    }
    
    private fun launchPickFolderForDecryption() {
        pendingAction = "decrypt"
        launchPickFolder()
    }
    
    private fun saveEncryptedToPickedFolder() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val secret = pendingEncryptionSecret ?: return@launch
                val suggestedName = pendingSuggestedName ?: "encrypted.pqrypt2"
                
                // Create output file in picked folder
                val outputUri = createFileInFolder(pickedFolderUri!!, suggestedName)
                    ?: throw IllegalStateException("Failed to create output file")
                
                // Open file descriptors for streaming
                val inputFd = contentResolver.openFileDescriptor(selectedFileUri!!, "r")
                    ?: throw IllegalStateException("Failed to open input file")
                val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
                    ?: throw IllegalStateException("Failed to open output file")
                
                try {
                    val startTime = System.currentTimeMillis()
                    
                    // Update UI to show processing status
                    withContext(Dispatchers.Main) {
                        binding.tvOutputPath.text = "Started processing your file, please wait...."
                    }
                    
                    // Call streaming encryption
                    val result = RustyCrypto.tripleEncryptFd(secret, isUsingKeyFile, inputFd.fd, outputFd.fd)
                    
                    if (result != 0) {
                        throw IllegalStateException("Encryption failed with code: $result")
                    }
                    
                    val elapsedTime = System.currentTimeMillis() - startTime
                    val elapsedSeconds = elapsedTime / 1000.0
                    
                    withContext(Dispatchers.Main) {
                        val outputPath = getFullPath(outputUri)
                        binding.tvOutputPath.text = "✅ Encrypted to: $outputPath (${String.format("%.1f", elapsedSeconds)}s)"
                        Toast.makeText(this@FileEncryptionActivity, "File encrypted in ${String.format("%.1f", elapsedSeconds)}s", Toast.LENGTH_SHORT).show()
                        clearPendingState()
                    }
                } finally {
                    inputFd.close()
                    outputFd.close()
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileEncryptionActivity, "Encryption error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    private fun saveDecryptedToPickedFolder() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val secret = pendingDecryptionSecret ?: return@launch
                val suggestedName = pendingSuggestedName ?: "decrypted.bin"
                
                // Create output file in picked folder
                val outputUri = createFileInFolder(pickedFolderUri!!, suggestedName)
                    ?: throw IllegalStateException("Failed to create output file")
                
                // Open file descriptors for streaming
                val inputFd = contentResolver.openFileDescriptor(selectedFileUri!!, "r")
                    ?: throw IllegalStateException("Failed to open input file")
                val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
                    ?: throw IllegalStateException("Failed to open output file")
                
                try {
                    val startTime = System.currentTimeMillis()
                    
                    // Update UI to show processing status
                    withContext(Dispatchers.Main) {
                        binding.tvOutputPath.text = "Started processing your file, please wait...."
                    }
                    
                    // Call streaming decryption
                    val result = RustyCrypto.tripleDecryptFd(secret, isUsingKeyFile, inputFd.fd, outputFd.fd)
                    if (result != 0) {
                        // Delete partial output on failure
                        try {
                            contentResolver.delete(outputUri, null, null)
                        } catch (deleteEx: Exception) {
                        }
                        val errorMessage = when (result) {
                            RustyCrypto.CRYPTO_ERROR_DECRYPTION_FAILED -> "Authentication/decryption failed. This may be due to file corruption, tampering, or wrong password/key file."
                            RustyCrypto.CRYPTO_ERROR_INVALID_INPUT -> "Invalid input file. The file may be corrupted or not a valid encrypted file."
                            RustyCrypto.CRYPTO_ERROR_NULL_POINTER -> "File access error. Please check file permissions."
                            else -> "Decryption failed with error code: $result. This may be due to file corruption, tampering, or wrong password/key file."
                        }
                        throw IllegalStateException(errorMessage)
                    }
                    
                    val elapsedTime = System.currentTimeMillis() - startTime
                    val elapsedSeconds = elapsedTime / 1000.0
                    
                    withContext(Dispatchers.Main) {
                        val outputPath = getFullPath(outputUri)
                        binding.tvOutputPath.text = "✅ Decrypted to: $outputPath (${String.format("%.1f", elapsedSeconds)}s)"
                        Toast.makeText(this@FileEncryptionActivity, "File decrypted in ${String.format("%.1f", elapsedSeconds)}s", Toast.LENGTH_SHORT).show()
                        clearPendingState()
                    }
                } finally {
                    inputFd.close()
                    outputFd.close()
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMessage = if (e.message?.contains("Authentication/decryption failed") == true || 
                                           e.message?.contains("tampering") == true) {
                        e.message
                    } else {
                        "Decryption error: ${e.message}"
                    }
                    Toast.makeText(this@FileEncryptionActivity, errorMessage, Toast.LENGTH_LONG).show()
                }
            }
        }
    }
    
    private fun clearPendingState() {
        pendingEncryptionSecret?.fill(0) // Zero sensitive data
        pendingDecryptionSecret?.fill(0)
        pendingEncryptionSecret = null
        pendingDecryptionSecret = null
        pendingSuggestedName = null
        pendingSuccessToast = null
    }
    
    private fun getParentDirectoryUri(fileUri: Uri): Uri? {
        return try {
            // For content URIs from DocumentsContract, try to get parent directory
            if (fileUri.scheme == "content" && fileUri.authority?.contains("com.android.externalstorage.documents") == true) {
                val documentId = DocumentsContract.getDocumentId(fileUri)
                val parts = documentId.split(":")
                if (parts.size >= 2) {
                    val path = parts[1]
                    val parentPath = path.substringBeforeLast("/")
                    if (parentPath.isNotEmpty() && parentPath != path) {
                        val parentDocId = "${parts[0]}:$parentPath"
                        val treeUri = DocumentsContract.buildTreeDocumentUri(fileUri.authority, parentDocId)
                        // Try to take persistable permission for the parent directory
                        try {
                            contentResolver.takePersistableUriPermission(
                                treeUri,
                                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                            )
                        } catch (e: Exception) {
                            // Permission might not be available, but we can still try to use the URI
                        }
                        return treeUri
                    }
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }
    
    private fun saveEncryptedToSameLocation(parentUri: Uri, fileName: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val secret = pendingEncryptionSecret ?: return@launch
                
                // Create output file in same directory as input
                val outputUri = createFileInFolder(parentUri, fileName)
                    ?: throw IllegalStateException("Failed to create output file in same directory")
                
                // Open file descriptors for streaming
                val inputFd = contentResolver.openFileDescriptor(selectedFileUri!!, "r")
                    ?: throw IllegalStateException("Failed to open input file")
                val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
                    ?: throw IllegalStateException("Failed to open output file")
                
                try {
                    val startTime = System.currentTimeMillis()
                    
                    // Update UI to show processing status
                    withContext(Dispatchers.Main) {
                        binding.tvOutputPath.text = "Started processing your file, please wait...."
                    }
                    
                    // Call streaming encryption
                    val result = RustyCrypto.tripleEncryptFd(secret, isUsingKeyFile, inputFd.fd, outputFd.fd)
                    
                    if (result != 0) {
                        throw IllegalStateException("Encryption failed with code: $result")
                    }
                    
                    val elapsedTime = System.currentTimeMillis() - startTime
                    val elapsedSeconds = elapsedTime / 1000.0
                    
                    withContext(Dispatchers.Main) {
                        val outputPath = getFullPath(outputUri)
                        binding.tvOutputPath.text = "✅ Encrypted to: $outputPath (${String.format("%.1f", elapsedSeconds)}s)"
                        Toast.makeText(this@FileEncryptionActivity, "File encrypted in ${String.format("%.1f", elapsedSeconds)}s", Toast.LENGTH_SHORT).show()
                        clearPendingState()
                    }
                } finally {
                    inputFd.close()
                    outputFd.close()
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMessage = if (e.message?.contains("Authentication/decryption failed") == true || 
                                           e.message?.contains("tampering") == true) {
                        e.message
                    } else {
                        "Could not save to same location. ${e.message}"
                    }
                    Toast.makeText(this@FileEncryptionActivity, errorMessage, Toast.LENGTH_LONG).show()
                    // Fallback to folder picker
                    if (pickedFolderUri != null) {
                        saveEncryptedToPickedFolder()
                    } else {
                        launchPickFolderForEncryption()
                    }
                }
            }
        }
    }
    
    private fun saveDecryptedToSameLocation(parentUri: Uri, fileName: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val secret = pendingDecryptionSecret ?: return@launch
                
                // Create output file in same directory as input
                val outputUri = createFileInFolder(parentUri, fileName)
                    ?: throw IllegalStateException("Failed to create output file in same directory")
                
                // Open file descriptors for streaming
                val inputFd = contentResolver.openFileDescriptor(selectedFileUri!!, "r")
                    ?: throw IllegalStateException("Failed to open input file")
                val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
                    ?: throw IllegalStateException("Failed to open output file")
                
                try {
                    val startTime = System.currentTimeMillis()
                    
                    // Update UI to show processing status
                    withContext(Dispatchers.Main) {
                        binding.tvOutputPath.text = "Started processing your file, please wait...."
                    }
                    
                    // Call streaming decryption
                    val result = RustyCrypto.tripleDecryptFd(secret, isUsingKeyFile, inputFd.fd, outputFd.fd)
                    if (result != 0) {
                        // Delete partial output on failure
                        try {
                            contentResolver.delete(outputUri, null, null)
                        } catch (deleteEx: Exception) {
                        }
                        val errorMessage = when (result) {
                            RustyCrypto.CRYPTO_ERROR_DECRYPTION_FAILED -> "Authentication/decryption failed. This may be due to file corruption, tampering, or wrong password/key file."
                            RustyCrypto.CRYPTO_ERROR_INVALID_INPUT -> "Invalid input file. The file may be corrupted or not a valid encrypted file."
                            RustyCrypto.CRYPTO_ERROR_NULL_POINTER -> "File access error. Please check file permissions."
                            else -> "Decryption failed with error code: $result. This may be due to file corruption, tampering, or wrong password/key file."
                        }
                        throw IllegalStateException(errorMessage)
                    }
                    
                    val elapsedTime = System.currentTimeMillis() - startTime
                    val elapsedSeconds = elapsedTime / 1000.0
                    
                    withContext(Dispatchers.Main) {
                        val outputPath = getFullPath(outputUri)
                        binding.tvOutputPath.text = "✅ Decrypted to: $outputPath (${String.format("%.1f", elapsedSeconds)}s)"
                        Toast.makeText(this@FileEncryptionActivity, "File decrypted in ${String.format("%.1f", elapsedSeconds)}s", Toast.LENGTH_SHORT).show()
                        clearPendingState()
                    }
                } finally {
                    inputFd.close()
                    outputFd.close()
                }
                
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMessage = if (e.message?.contains("Authentication/decryption failed") == true || 
                                           e.message?.contains("tampering") == true) {
                        e.message
                    } else {
                        "Could not save to same location. ${e.message}"
                    }
                    Toast.makeText(this@FileEncryptionActivity, errorMessage, Toast.LENGTH_LONG).show()
                    // Fallback to folder picker
                    if (pickedFolderUri != null) {
                        saveDecryptedToPickedFolder()
                    } else {
                        launchPickFolderForDecryption()
                    }
                }
            }
        }
    }
    
    private fun createFileInFolder(folderUri: Uri, fileName: String): Uri? {
        return try {
            val docUri = DocumentsContract.buildDocumentUriUsingTree(
                folderUri,
                DocumentsContract.getTreeDocumentId(folderUri)
            )
            
            // Check if file already exists using DocumentFile to avoid system auto-renaming
            val treeDoc = DocumentFile.fromTreeUri(this, folderUri)
            val existingFiles = treeDoc?.listFiles()?.mapNotNull { it.name }?.toSet() ?: emptySet()
            
            // Generate unique filename by appending _copy if needed
            var uniqueFileName = fileName
            var copyCount = 0
            
            // Pre-check if original filename exists and start with _copy if it does
            while (existingFiles.contains(uniqueFileName) && copyCount <= 100) {
                copyCount++
                uniqueFileName = generateCopyFileName(fileName, copyCount)
            }
            
            // Now try to create the document with our pre-determined unique name
            return try {
                val resultUri = DocumentsContract.createDocument(
                    contentResolver,
                    docUri,
                    "application/octet-stream",
                    uniqueFileName
                )
                
                if (resultUri != null) {
                    // Verify the actual filename matches what we intended
                    val actualName = getFileName(resultUri)
                    if (actualName == uniqueFileName) {
                        resultUri
                    } else {
                        // System still modified the name, delete and try with next _copy iteration
                        contentResolver.delete(resultUri, null, null)
                        
                        // Try with next _copy iteration
                        var nextCopyCount = copyCount + 1
                        while (nextCopyCount <= 100) {
                            val nextFileName = generateCopyFileName(fileName, nextCopyCount)
                            if (!existingFiles.contains(nextFileName)) {
                                val nextUri = DocumentsContract.createDocument(
                                    contentResolver,
                                    docUri,
                                    "application/octet-stream",
                                    nextFileName
                                )
                                if (nextUri != null && getFileName(nextUri) == nextFileName) {
                                    return nextUri
                                }
                                nextUri?.let { contentResolver.delete(it, null, null) }
                            }
                            nextCopyCount++
                        }
                        null
                    }
                } else {
                    null
                }
            } catch (e: Exception) {
                null
            }
            
        } catch (e: Exception) {
            null
        }
    }
    
    private fun generateCopyFileName(originalName: String, copyCount: Int): String {
        // Split filename and extension
        val lastDotIndex = originalName.lastIndexOf('.')
        return if (lastDotIndex != -1) {
            val nameWithoutExt = originalName.substring(0, lastDotIndex)
            val extension = originalName.substring(lastDotIndex)
            
            if (copyCount == 1) {
                "${nameWithoutExt}_copy$extension"
            } else {
                // For multiple copies, keep appending _copy
                "${nameWithoutExt}" + "_copy".repeat(copyCount) + "$extension"
            }
        } else {
            // No extension
            if (copyCount == 1) {
                "${originalName}_copy"
            } else {
                // For multiple copies, keep appending _copy
                "${originalName}" + "_copy".repeat(copyCount)
            }
        }
    }

    private fun launchCreateDocument(suggestedName: String) { // Prompt user to create a new output document
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply { // Build create-document intent
            addCategory(Intent.CATEGORY_OPENABLE) // Ensure a selectable, savable document
            type = "application/octet-stream" // Generic binary MIME type
            putExtra(Intent.EXTRA_TITLE, suggestedName) // Pre-fill suggested filename
            // Try to hint the initial folder near the input file
            selectedFileUri?.let { inputUri -> // If we have an input, hint its location
                try {
                    putExtra("android.provider.extra.INITIAL_URI", inputUri) // Best-effort initial directory
                } catch (_: Exception) {
                    // Best-effort only
                }
            }
        }
        createDocumentLauncher.launch(intent) // Launch system UI
    }

    private fun launchPickFolder() { // Ask user to pick a destination folder (tree URI)
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply { // Build folder picker intent
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION) // Request and persist R/W access
            // Try to hint initial location near input
            selectedFileUri?.let { inputUri ->
                try { putExtra("android.provider.extra.INITIAL_URI", inputUri) } catch (_: Exception) {} // Optional hint
            }
        }
        pickFolderLauncher.launch(intent) // Launch system folder picker
    }

    private fun saveToPickedFolder() { // Save pending output bytes into the chosen folder
        val folderUri = pickedFolderUri // Destination folder (tree URI)
        val bytes = pendingOutputBytes // Data to write
        val name = pendingSuggestedName // Desired filename
        if (folderUri == null || bytes == null || name.isNullOrEmpty()) return // Abort if missing context

        try {
            val outUri = createUniqueDocument(folderUri, "application/octet-stream", name) // Create non-colliding file
            if (outUri != null) {
                contentResolver.openOutputStream(outUri)?.use { it.write(bytes) } // Write bytes
                // Extract timing from success toast and add to path display
                val timingInfo = pendingSuccessToast?.substringBefore(" (") ?: ""
                val timingPart = if (timingInfo.contains("in ")) timingInfo.substringAfter("in ") else ""
                binding.tvOutputPath.text = if (timingPart.isNotEmpty()) {
                    "⏱️ $timingPart - Saved to: ${getFullPath(outUri)}"
                } else {
                    "Saved to: ${getFullPath(outUri)}"
                } // Update UI with timing and target
                Toast.makeText(this, pendingSuccessToast ?: "Saved", Toast.LENGTH_SHORT).show() // Notify success
            } else {
                Toast.makeText(this, "Failed to create file in selected folder", Toast.LENGTH_LONG).show() // Report failure
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show() // Report error
        } finally {
            pendingOutputBytes = null // Clear pending buffers
            pendingSuggestedName = null // Clear suggested name
            pendingSuccessToast = null // Clear message
        }
    }

    private fun createUniqueDocument(treeUri: Uri, mime: String, desiredName: String): Uri? { // Create a non-colliding file in a picked folder
        val treeDoc = DocumentFile.fromTreeUri(this, treeUri) ?: return null // Represent the tree as a DocumentFile
        // Build existing names set (case-insensitive to be safe)
        val existing = treeDoc.listFiles().mapNotNull { it.name }.toSet() // Snapshot current filenames

        val dot = desiredName.lastIndexOf('.') // Split name and extension
        val base = if (dot > 0) desiredName.substring(0, dot) else desiredName
        val ext = if (dot > 0 && dot < desiredName.length - 1) desiredName.substring(dot + 1) else ""

        var candidateBase = base // Start with base name
        var candidate = if (ext.isEmpty()) candidateBase else "$candidateBase.$ext" // Initial candidate
        while (existing.contains(candidate)) { // Bump with _copy until unique
            candidateBase = "${candidateBase}_copy"
            candidate = if (ext.isEmpty()) candidateBase else "$candidateBase.$ext"
        }

        val parentDocId = DocumentsContract.getTreeDocumentId(treeUri) // Parent doc ID
        val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId) // Parent URI
        return DocumentsContract.createDocument(contentResolver, parentDocUri, mime, candidate) // Create file
    }

    private fun getFileName(uri: Uri): String { // Resolve a display name for a given content/file URI
        var result: String? = null // Working variable
        if (uri.scheme == "content") { // Prefer querying content resolver for display name
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use { // Auto-close when done
                if (it.moveToFirst()) { // Move to first row
                    val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME) // Column index
                    if (nameIndex >= 0) { // If column exists
                        result = it.getString(nameIndex) // Use provider-supplied display name
                    }
                }
            }
        }
        if (result == null) { // Fallback: parse from path
            result = uri.path // Raw path
            val cut = result?.lastIndexOf('/') // Find last slash
            if (cut != -1) {
                result = result?.substring(cut!! + 1) // Take basename
            }
        }
        return result ?: "unknown_file" // Final fallback
    }

    private fun getFullPath(uri: Uri): String { // Best-effort human-readable path/identifier for UI
        return try {
            // Try to get the actual file path
            val path = uri.path // Raw path from URI
            if (path != null && path.isNotEmpty()) { // If available
                path // Return path
            } else {
                // Fallback to URI string
                uri.toString() // Return full URI
            }
        } catch (e: Exception) {
            // Fallback to filename if path extraction fails
            getFileName(uri) // Use display name
        }
    }

    private fun readFirstNBytes(uri: Uri, n: Int): ByteArray? { // Read up to n bytes from a content URI
        return try {
            contentResolver.openInputStream(uri)?.use { input -> // Open stream to URI
                val buffer = ByteArray(n) // Allocate temp buffer
                val read = input.read(buffer, 0, n) // Read at most n bytes
                if (read <= 0) null else buffer.copyOf(read) // Return exact-length slice or null
            }
        } catch (e: Exception) {
            null // On any IO error, return null
        }
    }

    // Read entire file contents into memory; caller should ensure size is reasonable for a key file
    private fun readAllBytes(uri: Uri): ByteArray? { // Load full content for small files (key material)
        return try {
            contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes() // Read all bytes into a new array
            }
        } catch (e: Exception) {
            null // On failure, signal by returning null
        }
    }

    private fun updateButtonStates() {
        val canEncryptDecrypt = selectedFileUri != null && passwordKey != null
        binding.btnEncrypt.isEnabled = canEncryptDecrypt
        binding.btnDecrypt.isEnabled = canEncryptDecrypt
    }

    // Add helper function to get filename from URI
    private fun getFileNameFromUri(uri: Uri): String? { // Best-effort display name from content or file URI
        var fileName: String? = null // Working variable
        if (uri.scheme == "content") { // Prefer provider's DISPLAY_NAME
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME) // Column index
                    if (nameIndex != -1) {
                        fileName = it.getString(nameIndex) // Use provider-supplied name
                    }
                }
            }
        }
        if (fileName == null) { // Fallback to path parsing
            fileName = uri.path // May be null for some schemes
            val cut = fileName?.lastIndexOf('/') // Find basename
            if (cut != -1) {
                fileName = fileName?.substring(cut!! + 1)
            }
        }
        return fileName // Can still be null if not resolvable
    }

    private fun getRealPathFromURI(uri: Uri): String? { // Attempt to resolve a filesystem path (rarely needed with SAF)
        return try {
            when (uri.scheme) {
                "content" -> {
                    // For content URIs, we cannot reliably get the actual file path
                    // Instead, we should save to app directory
                    null // Indicate not resolvable
                }
                "file" -> {
                    // For file URIs, we can get the path directly
                    uri.path // Return raw path
                }
                else -> null // Unknown schemes
            }
        } catch (e: Exception) {
            null
        }
    }

    private data class Header(val originalLength: Int, val numChunks: Int, val binaryStart: Int, val salt: ByteArray?)

    private fun parseHeader(bytes: ByteArray): Header {

        var index = 0
        fun readLine(): String {
            val sb = StringBuilder()
            while (index < bytes.size && bytes[index] != ('\n'.code and 0xFF).toByte()) {
                sb.append(bytes[index].toInt().toChar())
                index++
            }
            if (index < bytes.size && bytes[index] == ('\n'.code and 0xFF).toByte()) index++
            return sb.toString()
        }

        // Expect mandatory PQRYPT magic header
        val first = readLine()
        if (first != "PQRYPT") {
            throw IllegalArgumentException("Not a valid PQrypt encrypted file (missing PQRYPT header)")
        }

        val lenLine = readLine()
        val chunksLine = readLine()
        if (!lenLine.all { it.isDigit() } || !chunksLine.all { it.isDigit() }) {
            throw IllegalArgumentException("Not a valid PQrypt encrypted file (invalid header numbers)")
        }

        val originalLength = lenLine.toInt()
        val numChunks = chunksLine.toInt()
        return Header(originalLength, numChunks, index, null)
    }

    // HKDF-Extract(salt, IKM) using HMAC-SHA256
    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray { // Compute PRK from salt and input keying material
        // RFC 5869: if salt is not provided, use a string of HashLen zeros
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) { 0 } else salt // Default salt to 32 zero bytes when empty
        val mac = Mac.getInstance("HmacSHA256") // Allocate HMAC-SHA256 instance
        val keySpec = SecretKeySpec(effectiveSalt, "HmacSHA256") // Wrap salt as HMAC key
        mac.init(keySpec) // Initialize MAC with salt
        return mac.doFinal(ikm) // PRK (32 bytes) = HMAC(salt, IKM)
    }

    // HKDF-Expand(PRK, info, L) using HMAC-SHA256
    private fun hkdfSha256Expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray { // Expand PRK to L bytes
        val mac = Mac.getInstance("HmacSHA256") // Allocate HMAC-SHA256 instance
        val keySpec = SecretKeySpec(prk, "HmacSHA256") // PRK becomes the HMAC key
        mac.init(keySpec) // Initialize MAC with PRK
 
    val hashLen = 32 // Output size of SHA-256
    val n = ((length + hashLen - 1) / hashLen) // Number of blocks to generate
    var t = ByteArray(0) // Previous block (T(0) = empty)
    val okm = ByteArray(length) // Output keying material buffer
    var pos = 0 // Current write position
    for (i in 1..n) { // Generate blocks T(1)..T(n)
        mac.reset() // Reset MAC state per block
        mac.update(t) // MAC previous block T(i-1)
        mac.update(info) // MAC context/application-specific info
        mac.update(i.toByte()) // MAC counter byte i
        t = mac.doFinal() // Compute T(i)
        val toCopy = minOf(hashLen, length - pos) // Bytes to copy from this block
        System.arraycopy(t, 0, okm, pos, toCopy) // Append to OKM
        pos += toCopy // Advance output position
    }
    return okm // Return expanded key material of requested length
}

}
