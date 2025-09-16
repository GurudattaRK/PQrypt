package com.pineapple.app // Package namespace for this Kotlin file

import android.app.Activity // For activity result status codes
import android.content.Intent // To launch pickers and SAF actions
import android.net.Uri // To reference selected files and tree URIs
import android.os.Bundle // Activity lifecycle state container
import android.os.Environment // Access to external storage directories (legacy usage)
import android.widget.Toast // Brief user-facing notifications
import androidx.activity.result.contract.ActivityResultContracts // Register-for-activity-result APIs
import androidx.appcompat.app.AppCompatActivity // Base class for activities with support features
import androidx.documentfile.provider.DocumentFile // SAF-friendly file/folder abstraction
import com.pineapple.app.databinding.ActivityFileEncryptionBinding // ViewBinding for activity_file_encryption.xml
import kotlinx.coroutines.CoroutineScope // Coroutines for async work and debouncing
import kotlinx.coroutines.Dispatchers // Coroutines for async work and debouncing
import kotlinx.coroutines.Job // Coroutines job management
import kotlinx.coroutines.delay // Coroutines delay function
import kotlinx.coroutines.launch // Coroutines for async work and debouncing
import kotlinx.coroutines.withContext // Coroutines for async work and debouncing
import java.io.File // File path helper (may be used when resolving names)
import java.io.FileInputStream // Stream for reading local files
import java.io.FileOutputStream // Stream for writing local files
import java.security.SecureRandom // CSPRNG if needed for salts/keys
import android.text.TextWatcher // Listen to password field changes
import android.text.Editable // Editable text passed to TextWatcher
import android.provider.OpenableColumns // For querying display name/size via content resolver
import javax.crypto.Mac // HMAC used in HKDF operations
import javax.crypto.spec.SecretKeySpec // Key wrapper for MAC
import android.provider.DocumentsContract // SAF contract constants/utilities

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
    private var pendingOutputBytes: ByteArray? = null // Bytes to save after encryption/decryption
    private var pendingSuggestedName: String? = null // Suggested filename for the create-document dialog
    private var pendingSuccessToast: String? = null // Message to show after successful save
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
                    // Store full contents; Argon2 can handle arbitrary length as password input
                    keyFileFirst128 = allBytes // Cache key bytes for derivation
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
                        binding.tvOutputPath.text = "Processing your file please wait...." // UX feedback
                        Toast.makeText(this, "Encryption started", Toast.LENGTH_SHORT).show() // Notify user
                        performEncryption() // Continue with encryption
                    }
                    "decrypt" -> {
                        pendingAction = null // Clear pending marker
                        binding.tvOutputPath.text = "Processing your file please wait...." // UX feedback
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
                        "⏱️ $timingPart - Saved to: $outUri"
                    } else {
                        "Saved to: $outUri"
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

    override fun onCreate(savedInstanceState: Bundle?) { // Activity entry point when created
        super.onCreate(savedInstanceState) // Call base implementation
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
            android.util.Log.d("FileEncryption", "Encrypt button clicked") // Trace action
            android.util.Log.d("FileEncryption", "selectedFileUri: $selectedFileUri") // Debug selected input
            android.util.Log.d("FileEncryption", "passwordKey: ${passwordKey?.size} bytes") // Debug key presence/size

            // Ensure password key is generated before encryption
            if (selectedFileUri != null) { // Proceed only if an input file has been chosen
                android.util.Log.d("FileEncryption", "File is selected, checking password key") // Trace state
                if (passwordKey == null && (binding.etPassword.text.isNotEmpty() || isUsingKeyFile)) { // Key missing but inputs present
                    android.util.Log.d("FileEncryption", "Password key is null, generating...") // Will derive now
                    if (isUsingKeyFile) deriveKeyFromKeyFilePreview() else generatePasswordKey() // Choose derivation source
                    // Wait a moment for key generation, then try again
                    CoroutineScope(Dispatchers.Main).launch { // Delay to allow async derivation to complete
                        delay(500)
                        if (passwordKey != null) { // If key now available
                            android.util.Log.d("FileEncryption", "Password key generated, starting encryption") // Proceed
                            if (pickedFolderUri == null) { // Ensure we have an output folder
                                pendingAction = "encrypt" // Remember desired action
                                launchPickFolder() // Ask user to choose folder
                            } else {
                                binding.tvOutputPath.text = "Processing your file please wait...." // Inform user
                                Toast.makeText(this@FileEncryptionActivity, "Encryption started", Toast.LENGTH_SHORT).show() // UX feedback
                                performEncryption() // Begin encryption workflow
                            }
                        } else { // Derivation still not ready/failed
                            android.util.Log.e("FileEncryption", "Password key generation failed") // Log error
                            Toast.makeText(this@FileEncryptionActivity, "Please wait for password key generation to complete", Toast.LENGTH_SHORT).show() // Notify user
                        }
                    }
                } else if (passwordKey != null) { // If key already present
                    android.util.Log.d("FileEncryption", "Password key exists, starting encryption")
                    if (pickedFolderUri == null) {
                        pendingAction = "encrypt"
                        launchPickFolder()
                    } else {
                        binding.tvOutputPath.text = "Processing your file please wait...."
                        Toast.makeText(this, "Encryption started", Toast.LENGTH_SHORT).show()
                        performEncryption()
                    }
                } else {
                    android.util.Log.e("FileEncryption", "No password entered")
                    Toast.makeText(this, if (isUsingKeyFile) "Please select files" else "Please select a file and enter password", Toast.LENGTH_SHORT).show()
                }
            } else {
                android.util.Log.e("FileEncryption", "No file selected")
                Toast.makeText(this, "Please select a file first", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnDecrypt.setOnClickListener { // Handle decrypt button press
            android.util.Log.d("FileEncryption", "Decrypt button clicked") // Trace action
            android.util.Log.d("FileEncryption", "selectedFileUri: $selectedFileUri") // Debug selected input
            android.util.Log.d("FileEncryption", "passwordKey: ${passwordKey?.size} bytes") // Debug key presence/size

            // Ensure password key is generated before decryption
            if (selectedFileUri != null) { // Proceed only if an input file has been chosen
                android.util.Log.d("FileEncryption", "File is selected, checking password key") // Trace state
                if (passwordKey == null && binding.etPassword.text.isNotEmpty()) { // Key missing but password entered
                    android.util.Log.d("FileEncryption", "Password key is null, generating...") // Will derive now
                    generatePasswordKey() // Derive from entered password
                    // Wait a moment for key generation, then try again
                    CoroutineScope(Dispatchers.Main).launch { // Delay to allow async derivation to complete
                        delay(500)
                        if (passwordKey != null) { // If key now available
                            android.util.Log.d("FileEncryption", "Password key generated, starting decryption") // Proceed
                            if (pickedFolderUri == null) { // Ensure we have an output folder
                                pendingAction = "decrypt" // Remember desired action
                                launchPickFolder() // Ask user to choose folder
                            } else {
                                binding.tvOutputPath.text = "Processing your file please wait...." // Inform user
                                Toast.makeText(this@FileEncryptionActivity, "Decryption started", Toast.LENGTH_SHORT).show() // UX feedback
                                performDecryption() // Begin decryption workflow
                            }
                        } else { // Derivation still not ready/failed
                            android.util.Log.e("FileEncryption", "Password key generation failed") // Log error
                            Toast.makeText(this@FileEncryptionActivity, "Please wait for password key generation to complete", Toast.LENGTH_SHORT).show() // Notify user
                        }
                    }
                } else if (passwordKey != null) { // If key already present
                    android.util.Log.d("FileEncryption", "Password key exists, starting decryption") // Proceed
                    if (pickedFolderUri == null) { // Ensure we have an output folder
                        pendingAction = "decrypt" // Remember desired action
                        launchPickFolder() // Ask user to choose folder
                    } else {
                        binding.tvOutputPath.text = "Processing your file please wait...." // Inform user
                        Toast.makeText(this, "Decryption started", Toast.LENGTH_SHORT).show() // UX feedback
                        performDecryption() // Start decryption
                    }
                } else { // No password provided
                    android.util.Log.e("FileEncryption", "No password entered") // Log issue
                    Toast.makeText(this, "Please select a file and enter password", Toast.LENGTH_SHORT).show() // Prompt user
                }
            } else { // No file chosen
                android.util.Log.e("FileEncryption", "No file selected") // Log issue
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
        android.util.Log.d("FileEncryption", "generatePasswordKey: password length=${password.length}")
        if (password.isNotEmpty()) { // Only derive when non-empty
            CoroutineScope(Dispatchers.IO).launch { // Work off the main thread
                try {
                    android.util.Log.d("FileEncryption", "About to call RustyCrypto.argon2Hash for password key")
                    // Argon2-only 128B with NO SALT (deterministic across platforms)
                    val salt = ByteArray(0) // Empty salt for deterministic behavior
                    val argonOut = RustyCrypto.argon2Hash( // Call into native to derive bytes
                        password.toByteArray(),
                        salt,
                        128
                    )
                    android.util.Log.d("FileEncryption", "argon2Hash completed, result size: ${argonOut?.size}")
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
                    android.util.Log.e("FileEncryption", "Error in generatePasswordKey: ${e.javaClass.simpleName}: ${e.message}", e)
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
        CoroutineScope(Dispatchers.IO).launch { // Run encryption off the main thread
            val startTime = System.currentTimeMillis() // Track timing
            try {
                android.util.Log.d("FileEncryption", "Starting encryption process") // Trace start
                val inputStream = contentResolver.openInputStream(selectedFileUri!!) // Open input stream for chosen file
                val fileBytes = inputStream?.readBytes() // Read entire file into memory
                inputStream?.close() // Close stream to free resources
                android.util.Log.d("FileEncryption", "File read, size: ${fileBytes?.size}") // Log size info

                if (fileBytes != null && (passwordKey != null || isUsingKeyFile)) { // Ensure we have input and some key source
                    // Check file size for chunked processing
                    val maxSinglePassSize = 128 * 1024 * 1024 // 128MB
                    if (fileBytes.size > maxSinglePassSize) {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@FileEncryptionActivity, "File too large (${fileBytes.size / (1024*1024)}MB). Maximum supported: 128MB", Toast.LENGTH_LONG).show()
                        }
                        return@launch
                    }
                    // Derive deterministic key with NO SALT
                    val fixedSalt = ByteArray(0) // Empty salt indicates PQRYPT deterministic mode
                    android.util.Log.d("FileEncryption", "Encryption - Salt size: ${fixedSalt.size}, isUsingKeyFile: $isUsingKeyFile")
                    val argonOut = if (isUsingKeyFile) { // Choose derivation source based on mode
                        val keySrc = keyFileFirst128 // Use cached key-file bytes
                            ?: throw IllegalStateException("No key file bytes available") // Safety check
                        android.util.Log.d("FileEncryption", "Encryption - Using key file, keySrc size: ${keySrc.size}")
                        RustyCrypto.argon2Hash(keySrc, fixedSalt, 128) // Derive 128 bytes
                    } else {
                        val password = binding.etPassword.text.toString() // Read password text
                        if (password.isEmpty()) { // Ensure non-empty password
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@FileEncryptionActivity, "Please enter a password", Toast.LENGTH_SHORT).show() // Prompt user
                            }
                            return@launch // Abort encryption
                        }
                        android.util.Log.d("FileEncryption", "Encryption - Using password, length: ${password.length}")
                        RustyCrypto.argon2Hash(password.toByteArray(), fixedSalt, 128) // Derive 128 bytes
                    }
                    if (argonOut == null || argonOut.size != 128) throw IllegalStateException("Argon2(128) failed during encryption") // Validate output
                    // Use Argon2 output directly for master key (saltless)
                    passwordKey = argonOut // Cache derived key for this session
                    currentSalt = null // No salt used in PQRYPT

                    android.util.Log.d("FileEncryption", "Derived master key for encryption (no salt)") // Trace
                    // Encrypt entire file using combined triple encrypt: returns IV||ciphertext(padded)||TAG
                    val totalLength = fileBytes.size // Original plaintext length
                    android.util.Log.d("FileEncryption", "About to call RustyCrypto.tripleEncrypt with key size: ${passwordKey!!.size}, data size: $totalLength")
                    val blob = RustyCrypto.tripleEncrypt(passwordKey!!, fileBytes) // Perform native encryption
                        ?: throw IllegalStateException("Encryption failed (null blob)") // Ensure success
                    android.util.Log.d("FileEncryption", "tripleEncrypt completed, blob size: ${blob.size}")
                    val ciphertextLen = blob.size - RustyCrypto.AES256_IV_SIZE - RustyCrypto.AES256_TAG_SIZE // Exclude IV/TAG
                    val chunkCount = if (ciphertextLen <= 0) 0 else (ciphertextLen / 128) // Compute 128-byte chunk count

                    // Assemble output bytes (header + blob) then prompt/save
                    val baos = java.io.ByteArrayOutputStream() // Buffer to assemble output
                    // New magic header without SALT (deterministic KDF)
                    baos.write("PQRYPT\n".toByteArray()) // Magic identifier line
                    baos.write(totalLength.toString().toByteArray()) // Original length line
                    baos.write("\n".toByteArray()) // Newline separator
                    baos.write(chunkCount.toString().toByteArray()) // Number of 128B chunks line
                    baos.write("\n".toByteArray()) // Newline separator
                    baos.write(blob) // Append IV||ciphertext||TAG
                    val outputBytes = baos.toByteArray() // Final encrypted bytes

                    val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "encrypted_file" // Suggest based on input
                    val suggestedName = "${inputFileName}.encrypted" // Append .encrypted suffix

                    val totalTime = System.currentTimeMillis() - startTime // Calculate total time
                    withContext(Dispatchers.Main) { // Switch to UI to handle save flow
                        pendingOutputBytes = outputBytes // Stash output for saving
                        pendingSuggestedName = suggestedName // Stash filename suggestion
                        pendingSuccessToast = "File encrypted in ${totalTime}ms (${String.format("%.2f", totalTime/1000.0)}s)" // Configure success message with timing
                        // If folder chosen (Option B), save directly; else prompt to pick folder
                        if (pickedFolderUri != null) {
                            saveToPickedFolder() // Direct save
                        } else {
                            launchPickFolder() // Ask user to choose destination
                        }
                    }
                } else {
                    android.util.Log.e("FileEncryption", "fileBytes or passwordKey is null") // Log missing prerequisites
                }
            } catch (e: Exception) { // Catch and report any errors
                android.util.Log.e("FileEncryption", "Encryption error: ${e.message}", e) // Log with stacktrace
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileEncryptionActivity, "Encryption error: ${e.message}", Toast.LENGTH_SHORT).show() // Notify user
                }
            }
        }
    }

    private fun performDecryption() { // Decrypt selected file using derived key
        CoroutineScope(Dispatchers.IO).launch { // Run off the main thread
            val startTime = System.currentTimeMillis() // Track timing
            try {
                // Create debug log file
                val debugFile = File(filesDir, "decrypt_debug.log")
                debugFile.writeText("Decryption Debug Log - ${System.currentTimeMillis()}\n")
                android.util.Log.d("FileEncryption", "Debug log created at: ${debugFile.absolutePath}")
                
                android.util.Log.d("FileEncryption", "Starting decryption process") // Trace start
                val inputStream = contentResolver.openInputStream(selectedFileUri!!) // Open encrypted input
                val fileBytes = inputStream?.readBytes() // Load entire file into memory
                inputStream?.close() // Close input stream
                android.util.Log.d("FileEncryption", "File read, size: ${fileBytes?.size}") // Log size

                if (fileBytes != null && passwordKey != null) {
                    // Check file size for chunked processing
                    val maxSinglePassSize = 128 * 1024 * 1024 // 128MB
                    if (fileBytes.size > maxSinglePassSize) {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@FileEncryptionActivity, "Encrypted file too large (${fileBytes.size / (1024*1024)}MB). Maximum supported: 128MB", Toast.LENGTH_LONG).show()
                        }
                        return@launch
                    }
                    android.util.Log.d("FileEncryption", "Password key size: ${passwordKey!!.size}")
                    // Parse header from raw bytes to avoid charset issues
                    val headerInfo = parseHeader(fileBytes) // Decode PQrypt header
                    val originalLength = headerInfo.originalLength // Expected plaintext length
                    val numChunks = headerInfo.numChunks // 128-byte chunks count (diagnostic)
                    val binaryStart = headerInfo.binaryStart // Offset where blob begins
                    val binaryData = fileBytes.sliceArray(binaryStart until fileBytes.size) // Extract IV||cipher||TAG
                    android.util.Log.d("FileEncryption", "Header parsed: originalLength=$originalLength, numChunks=$numChunks, binaryStart=$binaryStart") // Trace

                    // Re-derive key with NO SALT for PQRYPT
                    val salt = headerInfo.salt ?: ByteArray(0) // Use empty salt for PQRYPT (saltless)
                    android.util.Log.d("FileEncryption", "Salt size: ${salt.size}, isUsingKeyFile: $isUsingKeyFile")
                    val argonOut = if (isUsingKeyFile) {
                        val keySrc = keyFileFirst128
                            ?: throw IllegalStateException("No key file bytes available")
                        android.util.Log.d("FileEncryption", "Using key file, keySrc size: ${keySrc.size}")
                        RustyCrypto.argon2Hash(keySrc, salt, 128)
                    } else {
                        val password = binding.etPassword.text.toString() // Read password text
                        if (password.isEmpty()) { // Abort if empty
                            withContext(Dispatchers.Main) {
                                Toast.makeText(this@FileEncryptionActivity, "Please enter a password", Toast.LENGTH_SHORT).show() // Prompt user
                            }
                            return@launch // Exit coroutine
                        }
                        android.util.Log.d("FileEncryption", "Using password, length: ${password.length}")
                        RustyCrypto.argon2Hash(password.toByteArray(), salt, 128) // Derive 128 bytes via Argon2
                    }
                    if (argonOut == null || argonOut.size != 128) throw IllegalStateException("Argon2(128) failed during decryption") // Validate length
                    // Use Argon2 output directly for master key (saltless)
                    passwordKey = argonOut // Cache derived key
                    currentSalt = if (salt.isNotEmpty()) salt else null
                    android.util.Log.d("FileEncryption", "Re-derived master key (saltless for PQRYPT)") // Trace

                    // Combined triple decrypt: feed entire blob (IV||ciphertext||TAG)
                    android.util.Log.d("FileEncryption", "About to call RustyCrypto.tripleDecrypt with key size: ${passwordKey!!.size}, binary data size: ${binaryData.size}")
                    
                    // Log the first few bytes of the key and data for debugging
                    val keyPreview = passwordKey!!.take(16).joinToString(" ") { "%02x".format(it) }
                    val dataPreview = binaryData.take(16).joinToString(" ") { "%02x".format(it) }
                    android.util.Log.d("FileEncryption", "Key preview (first 16 bytes): $keyPreview")
                    android.util.Log.d("FileEncryption", "Data preview (first 16 bytes): $dataPreview")
                    debugFile.appendText("Key preview: $keyPreview\n")
                    debugFile.appendText("Data preview: $dataPreview\n")
                    
                    val combined = RustyCrypto.tripleDecrypt(passwordKey!!, binaryData) // Run native decrypt
                        ?: throw IllegalStateException("Decryption failed (null result)") // Ensure success
                    android.util.Log.d("FileEncryption", "tripleDecrypt completed, result size: ${combined.size}")
                    android.util.Log.d("FileEncryption", "Decryption completed, trimming to original length") // Info
                    val decryptedFile = if (originalLength <= combined.size) { // Trim padding if any
                        combined.copyOfRange(0, originalLength) // Slice to original length
                    } else { // Safety fallback if header length was larger than data
                        combined // Use as-is
                    }

                    val inputFileName = getFileNameFromUri(selectedFileUri!!) ?: "decrypted_file" // Determine base name
                    val suggestedName = if (inputFileName.endsWith(".encrypted")) { // Prefer removing known suffix
                        inputFileName.removeSuffix(".encrypted") // Restore original name
                    } else {
                        "${inputFileName}.decrypted" // Append suffix for clarity
                    }

                    val totalTime = System.currentTimeMillis() - startTime // Calculate total time
                    withContext(Dispatchers.Main) { // Switch back to UI to finalize output flow
                        pendingOutputBytes = decryptedFile // Stash bytes for saving
                        pendingSuggestedName = suggestedName // Stash suggested filename
                        pendingSuccessToast = "File decrypted in ${totalTime}ms (${String.format("%.2f", totalTime/1000.0)}s)" // Message with timing
                        if (pickedFolderUri != null) { // If user already chose an output folder
                            saveToPickedFolder() // Save directly
                        } else {
                            launchPickFolder() // Ask user to choose folder
                        }
                    }
                } else {
                    android.util.Log.e("FileEncryption", "fileBytes or passwordKey is null")
                }
            } catch (e: Exception) {
                android.util.Log.e("FileEncryption", "Decryption error: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileEncryptionActivity, "Decryption error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
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
                    "⏱️ $timingPart - Saved to: $outUri"
                } else {
                    "Saved to: $outUri"
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

    private fun updateButtonStates() { // Enable/disable actions based on current selections
        val canEncryptDecrypt = selectedFileUri != null && passwordKey != null // Need both file and key
        android.util.Log.d("FileEncryption", "updateButtonStates: selectedFileUri=${selectedFileUri != null}, passwordKey=${passwordKey != null}, canEncryptDecrypt=$canEncryptDecrypt") // Trace
        binding.btnEncrypt.isEnabled = canEncryptDecrypt // Toggle encrypt button
        binding.btnDecrypt.isEnabled = canEncryptDecrypt // Toggle decrypt button
        android.util.Log.d("FileEncryption", "Button states: encrypt=${binding.btnEncrypt.isEnabled}, decrypt=${binding.btnDecrypt.isEnabled}") // Trace
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
            android.util.Log.w("FileEncryption", "Cannot resolve URI path: ${e.message}") // Log warning
            null // Fallback to null
        }
    }

    private data class Header(val originalLength: Int, val numChunks: Int, val binaryStart: Int, val salt: ByteArray?)

    private fun parseHeader(bytes: ByteArray): Header {
        android.util.Log.d("FileEncryption", "parseHeader: Starting to parse header, bytes.size=${bytes.size}")

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
