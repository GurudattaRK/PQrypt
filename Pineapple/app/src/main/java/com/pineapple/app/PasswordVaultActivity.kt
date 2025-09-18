package com.pineapple.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import kotlinx.coroutines.*
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.pineapple.app.databinding.ActivityPasswordVaultBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.*

class PasswordVaultActivity : AppCompatActivity() { // UI to derive, display, and autofill passwords securely

    private lateinit var binding: ActivityPasswordVaultBinding // ViewBinding for this screen
    private lateinit var sharedPrefs: SharedPreferences // App-specific preferences store
    private var passwordLength: Int = 16 // Desired generated password length
    // Only store the 3 special character sets (last 3 of the 6 total sets)
    // First 3 sets (lowercase, uppercase, digits) are always enabled
    private var enabledSpecialSets = booleanArrayOf(true, true, true) // Toggles for special sets
    
    // Simplified - no pre-hashing, everything done on Generate button
    private var finalPasswordHash: ByteArray? = null // Final hash for password generation
    
    // Security enhancement: Variables for auto-clear functionality
    private var currentGeneratedPassword: String? = null // Last generated password kept for display
    private var clearPasswordHandler: Handler? = null // Schedules secure clear of password
    private var clearPasswordRunnable: Runnable? = null // Runnable that performs the clear
    private var countdownHandler: Handler? = null // Drives countdown label updates
    private var countdownRunnable: Runnable? = null // Runnable to decrement secondsRemaining
    private var secondsRemaining = 0 // Seconds left before auto-clear
    
    // No async operations needed anymore
    private var isGenerating = false // Prevent multiple simultaneous generations

    // Unsafe clipboard functionality
    private var clipboardClearHandler: Handler? = null // Timer to clear clipboard after warning use
    private var clipboardClearRunnable: Runnable? = null // Runnable to wipe clipboard content

    override fun onCreate(savedInstanceState: Bundle?) { // Activity entry point
        super.onCreate(savedInstanceState)
        binding = ActivityPasswordVaultBinding.inflate(layoutInflater) // Inflate binding
        setContentView(binding.root) // Attach layout

        sharedPrefs = getSharedPreferences("pqrypt_vault", Context.MODE_PRIVATE) // Preferences namespace
        loadSettings() // Initialize UI settings from storage
        setupUI() // Wire up interactions
        
        // Initialize handlers for auto-clear functionality
        clearPasswordHandler = Handler(Looper.getMainLooper()) // Runs password clear tasks on main
        countdownHandler = Handler(Looper.getMainLooper()) // Runs countdown updates on main
        clipboardClearHandler = Handler(Looper.getMainLooper()) // Runs clipboard wipe tasks on main
    }

    // Clears local timers and UI, and sensitive locals, but DOES NOT clear the Autofill service's pending password.
    private fun clearLocalStatePreservingAutofillService() { // Reset local sensitive state; keep service password
        // // Log.d("PasswordVault", "Clearing local state (preserving Autofill service)") // Trace

        // Stop timers
        clearPasswordRunnable?.let { clearPasswordHandler?.removeCallbacks(it) } // Cancel clear callback
        countdownRunnable?.let { countdownHandler?.removeCallbacks(it) } // Cancel countdown updates

        // Clear local password variables (best effort memory overwrite)
        currentGeneratedPassword?.let { pw -> // Overwrite characters where possible
            val chars = pw.toCharArray()
            java.util.Arrays.fill(chars, '\u0000') // Best-effort wipe
        }
        currentGeneratedPassword = null // Drop strong reference

        finalPasswordHash?.let { hash -> java.util.Arrays.fill(hash, 0) } // Wipe hash bytes
        finalPasswordHash = null // Clear reference

        // Clear UI display only
        binding.tvGeneratedPassword.text = "🔒 Password hidden while app is in background. Autofill remains available for 60s." // Inform user
    }

    override fun onDestroy() { // Cleanup when activity is destroyed
        super.onDestroy()
        
        // Cancel any running password generation to prevent crashes and memory leaks
        passwordGenerationJob?.cancel()
        
        // Preserve Autofill pending password even if activity is destroyed within the 60s window.
        // Let the service timer handle clearing; only clear local state here.
        clearLocalStatePreservingAutofillService() // Reset local sensitive data
        
        // // Log.d("PasswordVault", "Activity destroyed, all operations cancelled")
    }

    override fun onPause() { // When app goes to background
        super.onPause()
        // Preserve Autofill pending password when app goes to background.
        // Only clear local UI/state; the service's 60s timer will handle secure clearing.
        clearLocalStatePreservingAutofillService() // Drop local data; service retains password temporarily
    }

    private fun loadSettings() { // Restore UI-configurable options from preferences
        passwordLength = sharedPrefs.getInt("password_length", 16) // Length slider persisted value
        // Load only the special character sets (sets 4, 5, 6)
        enabledSpecialSets[0] = sharedPrefs.getBoolean("set_special1", true) // ~!@#$%^&*()
        enabledSpecialSets[1] = sharedPrefs.getBoolean("set_special2", true) // /.,';][=-
        enabledSpecialSets[2] = sharedPrefs.getBoolean("set_special3", true) // ><":}{+_
    }

    private fun setupUI() { // Wire UI listeners and dynamic behaviors
        binding.btnBack.setOnClickListener { // Navigate back, clearing sensitive state first
            clearAllPasswordData() // Proactively wipe and cancel timers
            finish() // Close activity
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "password_vault"))
        }

        // No focus-based hashing - everything happens on Generate button

        binding.btnGeneratePassword.setOnClickListener { // Gate final generation behind biometric/device credential
            // Validate required fields first
            val appName = binding.etAppName.text.toString().trim()
            val masterPassword = binding.etMasterPassword.text.toString().trim()
            
            if (appName.isEmpty()) {
                Toast.makeText(this, "App/Website name is required", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            
            if (masterPassword.isEmpty()) {
                Toast.makeText(this, "Master password is required", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            
            // No pre-hashing - just proceed to generation
            
            val biometricManager = BiometricManager.from(this)
            when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    val promptInfo = BiometricPrompt.PromptInfo.Builder() // Configure authentication prompt
                        .setTitle("Authenticate to Generate Password")
                        .setSubtitle("Use your fingerprint, face, or device PIN/pattern/password")
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                        .build()

                    val biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() { // Callback for auth events
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            super.onAuthenticationError(errorCode, errString)
                            Toast.makeText(this@PasswordVaultActivity, "Authentication error: $errString", Toast.LENGTH_SHORT).show() // Inform user
                        }

                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            generateFinalPassword() // Proceed with password derivation and display
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            Toast.makeText(this@PasswordVaultActivity, "Authentication failed", Toast.LENGTH_SHORT).show() // Inform user
                        }
                    })

                    biometricPrompt.authenticate(promptInfo)
                }
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    Toast.makeText(this, "No biometric hardware available", Toast.LENGTH_SHORT).show() // Device lacks supported sensors
                }
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    Toast.makeText(this, "Biometric hardware unavailable", Toast.LENGTH_SHORT).show() // Temporary unavailability
                }
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    Toast.makeText(this, "No biometric data enrolled. Please set up biometrics or device lock.", Toast.LENGTH_LONG).show() // Require enrollment
                }
                else -> {
                    Toast.makeText(this, "Authentication not available", Toast.LENGTH_SHORT).show() // Generic fallback
                }
            }
        }

        binding.btnSettings.setOnClickListener { // Open settings screen
            startActivity(Intent(this, PasswordSettingsActivity::class.java)) // Navigate
        }


        // Unsafe clipboard copy button with security warning
        binding.btnUnsafeClipboardCopy.setOnClickListener { // Allow copying to clipboard (discouraged), with warning
            showClipboardSecurityWarning() // Show warning and handle copy+wipe
        }

        binding.btnAutofillStatus.setOnClickListener { // Check and manage autofill service status
            checkAndManageAutofillService()
        }
    }

    override fun onResume() { // Reload settings when returning to foreground
        super.onResume()
        loadSettings() // Refresh configurable options
        updateAutofillStatusButton() // Update autofill button text based on current status
    }

    // Removed all the complex pre-hashing functions - everything is now done in generateFinalPassword()

    // Add thread safety with coroutine job tracking
    private var passwordGenerationJob: kotlinx.coroutines.Job? = null
    
    private fun generateFinalPassword() { // Main flow to produce and expose password for Autofill
        // Log.d("PasswordVault", "generateFinalPassword: start") // Trace
        
        // Cancel any existing password generation to prevent concurrent operations
        passwordGenerationJob?.cancel()
        
        // Log.d("PasswordVault", "Native library check starting...")
        
        // Check if native library is loaded before proceeding
        if (!checkNativeLibrary()) {
            // Log.e("PasswordVault", "Native library check failed")
            Toast.makeText(this, "Error: Native library not available. Please restart the app.", Toast.LENGTH_LONG).show()
            return
        }
        // Log.d("PasswordVault", "Native library check passed")
        
        // Clear any existing password data first
        clearAllPasswordData() // Ensure clean slate and cancel timers
        
        // Read current inputs directly so we don't rely on focus-change events
        val appName = binding.etAppName.text.toString().trim() // App identifier (namespace)
        val appPassword = binding.etAppPassword.text.toString() // Optional per-app secret
        val masterPassword = binding.etMasterPassword.text.toString() // User's master

        if (appName.isBlank()) { // Require app name
            Toast.makeText(this, "Please enter app name", Toast.LENGTH_SHORT).show()
            return // Abort
        }
        if (masterPassword.isBlank()) { // Require master password
            Toast.makeText(this, "Please enter master password", Toast.LENGTH_SHORT).show()
            return // Abort
        }

        // Disable button to prevent multiple clicks
        binding.btnGeneratePassword.isEnabled = false // Prevent reentry
        binding.btnGeneratePassword.text = "Generating..." // UI feedback

        // Run all Argon2 operations on background thread to prevent UI blocking and crashes
        passwordGenerationJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                // Log.d("PasswordVault", "Starting unified 128-byte derivation on background thread")
                val finalHash = RustyCrypto.derivePasswordHashUnified128(
                    appName.toByteArray(),
                    appPassword.toByteArray(),
                    masterPassword.toByteArray()
                )
                if (!isActive) return@launch
                if (finalHash == null || finalHash.size != 128) {
                    // Log.e("PasswordVault", "Unified 128-byte derivation failed or invalid size: ${finalHash?.size}")
                    withContext(Dispatchers.Main) {
                        binding.btnGeneratePassword.isEnabled = true
                        binding.btnGeneratePassword.text = "Generate Password"
                        Toast.makeText(this@PasswordVaultActivity, "Error: Password derivation failed", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                // Check if cancelled before password generation
                if (!isActive) return@launch

                // Log.d("PasswordVault", "Unified hash successful, result size: ${finalHash.size}")
                
                // Store for later use
                finalPasswordHash = finalHash
                
                // Generate password using unified API (bitmask for specials)
                // Log.d("PasswordVault", "About to call RustyCrypto.generatePasswordUnified")
                var specialsMask = 0
                enabledSpecialSets.forEachIndexed { index, enabled ->
                    if (enabled) {
                        specialsMask = specialsMask or (1 shl index)
                    }
                }
                val appPasswordBytes = if (appPassword.isNotEmpty()) appPassword.toByteArray() else null
                val generatedPassword = RustyCrypto.generatePasswordUnified(
                    appName.toByteArray(),
                    appPasswordBytes,
                    masterPassword.toByteArray(),
                    passwordLength,
                    specialsMask
                ) as String?
                
                // Switch back to main thread for UI updates
                withContext(Dispatchers.Main) {
                    if (generatedPassword.isNullOrEmpty()) {
                        // Log.e("PasswordVault", "Generated password is null or empty")
                        binding.btnGeneratePassword.isEnabled = true
                        binding.btnGeneratePassword.text = "Generate Password"
                        Toast.makeText(this@PasswordVaultActivity, "Error: Password generation failed", Toast.LENGTH_SHORT).show()
                        return@withContext
                    }
                    
                    // Update UI with generated password
                    PQryptAutofillService.setPasswordForAutofill(generatedPassword)
                    currentGeneratedPassword = generatedPassword
                    
                    // Display password
                    binding.tvGeneratedPassword.text = "Password: $generatedPassword\n\n⏱️ Available for Autofill. Will be cleared in 60 seconds"
                    Toast.makeText(this@PasswordVaultActivity, "Password ready for Autofill. Will be cleared in 60 seconds.", Toast.LENGTH_LONG).show()
                    
                    // Show the unsafe clipboard copy button
                    binding.btnUnsafeClipboardCopy.visibility = android.view.View.VISIBLE
                    
                    // Start 60-second countdown and auto-clear
                    startPasswordClearCountdown()
                    
                    // Optionally save to stored passwords
                    savePasswordIfRequested(generatedPassword)
                    
                    // Log.d("PasswordVault", "Password generation and display complete")
                    binding.btnGeneratePassword.isEnabled = true
                    binding.btnGeneratePassword.text = "Generate Password"
                }
                
            } catch (e: Exception) {
                // Log.e("PasswordVault", "Error in password generation", e)
                withContext(Dispatchers.Main) {
                    binding.btnGeneratePassword.isEnabled = true
                    binding.btnGeneratePassword.text = "Generate Password"
                    Toast.makeText(this@PasswordVaultActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun startPasswordClearCountdown() { // Begin 60s countdown and schedule secure clear
        secondsRemaining = 60 // Initialize timer duration
        
        // Clear any existing countdown
        clearPasswordRunnable?.let { clearPasswordHandler?.removeCallbacks(it) } // Cancel prior clear
        countdownRunnable?.let { countdownHandler?.removeCallbacks(it) } // Cancel prior countdown
        
        // Create countdown display runnable
        countdownRunnable = object : Runnable { // Updates UI each second
            override fun run() {
                if (secondsRemaining > 0) {
                    val currentPassword = currentGeneratedPassword
                    if (currentPassword != null) {
                        binding.tvGeneratedPassword.text = "Password: $currentPassword\n\n⏱️ Clearing in $secondsRemaining seconds" // Show remaining time
                    }
                    secondsRemaining-- // Decrement timer
                    countdownHandler?.postDelayed(this, 1000) // Schedule next tick
                } else {
                    clearAllPasswordData() // Time's up – wipe
                }
            }
        }
        
        // Create auto-clear runnable
        clearPasswordRunnable = Runnable {
            clearAllPasswordData() // Ensure wipe even if UI not updating
        }
        
        // Start countdown display
        countdownHandler?.post(countdownRunnable!!) // Kick off updates
        
        // Schedule auto-clear after 60 seconds
        clearPasswordHandler?.postDelayed(clearPasswordRunnable!!, 60000) // Final wipe timer
    }

    private fun clearAllPasswordData() { // Wipe generated secrets, timers, UI, and Autofill pending value
        // Log.d("PasswordVault", "Clearing all password data") // Trace
        
        clearPasswordRunnable?.let { clearPasswordHandler?.removeCallbacks(it) } // Cancel clear timer
        countdownRunnable?.let { countdownHandler?.removeCallbacks(it) } // Cancel countdown
        
        // Clear clipboard timer if active
        clipboardClearRunnable?.let { clipboardClearHandler?.removeCallbacks(it) } // Cancel clipboard wipe
        
        PQryptAutofillService.clearPendingPassword() // Tell service to drop pending password
        
        currentGeneratedPassword?.let { password -> // Best-effort overwrite of displayed password
            val charArray = password.toCharArray()
            Arrays.fill(charArray, '\u0000')
        }
        currentGeneratedPassword = null // Drop reference
        
        finalPasswordHash?.let { hash -> // Overwrite final hash bytes
            Arrays.fill(hash, 0.toByte())
        }
        finalPasswordHash = null // Drop reference
        
        binding.tvGeneratedPassword.text = "🔒 Password cleared for security" // Update UI message
        
        // Hide the unsafe clipboard copy button
        binding.btnUnsafeClipboardCopy.visibility = android.view.View.GONE // Hide button
        
        Toast.makeText(this, "🔒 All password data cleared from memory", Toast.LENGTH_SHORT).show() // Notify
        
        // Log.d("PasswordVault", "Password data clearing completed") // Trace
    }

    private fun savePasswordIfRequested(password: String) { // Persist entry if user opted in (note: plaintext SharedPreferences)
        val appName = binding.etAppName.text.toString() // Key name
        val appPassword = binding.etAppPassword.text.toString() // Optional hint/secret
        
        if (appName.isNotEmpty()) {
            // Save to SharedPreferences (in a real app, this should be encrypted)
            val savedPasswords = sharedPrefs.getStringSet("saved_passwords", emptySet())?.toMutableSet() ?: mutableSetOf() // Load set
            val passwordEntry = "$appName|$appPassword|$password" // Simple pipe-delimited format
            savedPasswords.add(passwordEntry) // Add/overwrite
            
            sharedPrefs.edit().putStringSet("saved_passwords", savedPasswords).apply() // Persist
        }
    }

    private fun showClipboardSecurityWarning() { // Strong warning against clipboard usage
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("⚠️ SECURITY WARNING") // Emphasize risk
            .setMessage("Using clipboard is DANGEROUS and UNSAFE!\n\n" +
                    "• Other apps can read clipboard data\n" +
                    "• Clipboard history may store your password\n" +
                    "• Password will be cleared in 21 seconds\n\n" +
                    "Recommended: Use Autofill instead of clipboard.\n\n" +
                    "Continue anyway?") // Detailed risks and safer alternative
            .setPositiveButton("I Understand - Copy Anyway") { _, _ ->
                copyPasswordToClipboardUnsafely() // Proceed despite warning
            }
            .setNegativeButton("Cancel (Recommended)") { dialog, _ ->
                dialog.dismiss() // Abort
                Toast.makeText(this, "Good choice! Use Autofill for security.", Toast.LENGTH_SHORT).show() // Encourage best practice
            }
            .setCancelable(false) // Force explicit choice
            .show() // Display dialog
    }

    private fun copyPasswordToClipboardUnsafely() { // Copy password to system clipboard (discouraged)
        val password = currentGeneratedPassword // The generated value
        if (password != null) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager // System clipboard
            val clip = ClipData.newPlainText("password", password) // Plain text item
            clipboard.setPrimaryClip(clip) // Place on clipboard
            
            Toast.makeText(this, "Password copied to clipboard (UNSAFE!)", Toast.LENGTH_SHORT).show() // Warn user
            
            // Clear clipboard after 21 seconds
            clipboardClearRunnable = Runnable {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    clipboard.clearPrimaryClip() // API 28+
                } else {
                    // Fallback for API < 28: overwrite with empty clip
                    clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
                Toast.makeText(this, "Clipboard cleared for security", Toast.LENGTH_SHORT).show() // Confirm wipe
            }
            clipboardClearHandler?.postDelayed(clipboardClearRunnable!!, 21000) // Schedule wipe
        }
    }

    private fun checkNativeLibrary(): Boolean { // Sanity-check that JNI is loaded and functional
        return try {
            // Test a simple native call to verify library is loaded
            val testSalt = ByteArray(16) { 0 } // Dummy salt
            val testPassword = "test".toByteArray() // Dummy input
            RustyCrypto.argon2Hash(testPassword, testSalt, 32) // Should succeed
            true // JNI OK
        } catch (e: UnsatisfiedLinkError) {
            // Log.e("PasswordVault", "Native library not loaded", e) // JNI missing
            false
        } catch (e: Exception) {
            // Log.e("PasswordVault", "Error testing native library", e) // Other failure
            false
        }
    }

    private fun isAutofillServiceEnabled(): Boolean { // Check if this app is set as autofill service
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val autofillManager = getSystemService(android.view.autofill.AutofillManager::class.java)
            autofillManager?.hasEnabledAutofillServices() ?: false
        } else {
            false // Autofill not available on older versions
        }
    }

    private fun updateAutofillStatusButton() { // Update button text based on autofill service status
        if (isAutofillServiceEnabled()) {
            binding.btnAutofillStatus.text = "✅ Autofill Service Active"
            binding.btnAutofillStatus.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_green_dark)
        } else {
            binding.btnAutofillStatus.text = "⚙️ Enable Autofill Service"
            binding.btnAutofillStatus.backgroundTintList = ContextCompat.getColorStateList(this, android.R.color.holo_orange_dark)
        }
    }

    private fun checkAndManageAutofillService() { // Check status and guide user to settings if needed
        if (isAutofillServiceEnabled()) {
            Toast.makeText(this, "✅ PQrypt Autofill Service is already enabled!", Toast.LENGTH_SHORT).show()
        } else {
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Enable Autofill Service")
                .setMessage("PQrypt Autofill Service is not enabled. Would you like to go to Settings to enable it?\n\n" +
                        "This will allow you to automatically fill passwords in other apps and websites.")
                .setPositiveButton("Go to Settings") { _, _ ->
                    openAutofillSettings()
                }
                .setNegativeButton("Cancel") { dialog, _ ->
                    dialog.dismiss()
                }
                .show()
        }
    }

    private fun openAutofillSettings() { // Navigate to autofill service settings
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                intent.data = android.net.Uri.parse("package:${packageName}")
                startActivity(intent)
            } else {
                Toast.makeText(this, "Autofill service requires Android 8.0 or higher", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            // Log.e("PasswordVault", "Error opening autofill settings", e)
            // Fallback to general settings
            try {
                val intent = Intent(Settings.ACTION_SETTINGS)
                startActivity(intent)
                Toast.makeText(this, "Please navigate to System > Languages & input > Autofill service", Toast.LENGTH_LONG).show()
            } catch (e2: Exception) {
                Toast.makeText(this, "Unable to open settings. Please manually enable autofill service.", Toast.LENGTH_LONG).show()
            }
        }
    }

}
