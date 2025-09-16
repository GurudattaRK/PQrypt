package com.pineapple.app // Defines the package namespace for this Kotlin file

import android.content.Intent // Android class used to start activities or services
import androidx.appcompat.app.AppCompatActivity // Base class for activities using the support ActionBar
import android.os.Bundle // Container for passing activity state across configuration changes
import android.os.Build // Provides device/build version constants for API checks
import android.provider.Settings // Access to system settings constants (not used directly here after cleanup)
import android.util.Log // Logging utility for debug output
import android.view.autofill.AutofillManager // Manager to query autofill availability and status
import android.widget.Toast // UI helper to show brief messages (not used in current code)
import android.widget.Button // Button widget class (referenced via view binding rather than findViewById)
import com.pineapple.app.databinding.ActivityMainBinding // Generated binding for activity_main.xml layout

class MainActivity : AppCompatActivity() { // Main launcher activity for the app

    private lateinit var binding: ActivityMainBinding // Late-initialized view binding reference for the layout

    override fun onCreate(savedInstanceState: Bundle?) { // Lifecycle callback invoked when activity is created
        super.onCreate(savedInstanceState) // Call to superclass to perform default initialization

        binding = ActivityMainBinding.inflate(layoutInflater) // Inflate the layout via view binding to get typed views
        setContentView(binding.root) // Set the activity content to the root view from the binding

        // Help button (top-right) opens help screen
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "main"))
        }

        // Set up the three main buttons // Register click listener to open FileEncryptionActivity
        binding.btnFileEncryption.setOnClickListener {
            startActivity(Intent(this, FileEncryptionActivity::class.java)) // Launch file encryption screen
        }

        binding.btnPqcKeyExchange.setOnClickListener {
            startActivity(Intent(this, KeyExchangeModeActivity::class.java)) // Launch key exchange mode selection screen
        }

        binding.btnPasswordVault.setOnClickListener {
            startActivity(Intent(this, PasswordVaultActivity::class.java)) // Launch password vault screen
        }

        // Autofill debug: initial status on launch // Log device support and status for Autofill framework
        debugAutofillSupport()

        // Removed Test Autofill button and handler // Historical note: legacy test UI was removed
    }

    private fun debugAutofillSupport() { // Helper method to log Autofill capability and status
        Log.d("AutofillDebug", "Android version: ${Build.VERSION.SDK_INT}") // Log the device's SDK version
        Log.d("AutofillDebug", "Minimum required: ${Build.VERSION_CODES.O} (26)") // Log the minimum SDK needed for Autofill

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) { // Check if the device supports the Autofill framework (API 26+)
            val afm = getSystemService(AutofillManager::class.java) // Obtain AutofillManager instance from the system
            Log.d("AutofillDebug", "AutofillManager available: ${afm != null}") // Log whether manager is present
            Log.d("AutofillDebug", "Autofill enabled: ${afm?.isEnabled}") // Log whether autofill is enabled by user/device
            Log.d("AutofillDebug", "Autofill supported: ${afm?.isAutofillSupported}") // Log whether autofill is supported by service
        } else {
            Log.d("AutofillDebug", "Device too old for autofill") // Fallback log for devices below API 26
        }
    }
}