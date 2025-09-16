package com.pqrypt.app

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.SeekBar
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivityPasswordSettingsBinding

class PasswordSettingsActivity : AppCompatActivity() { // Configure password length and special sets

    private lateinit var binding: ActivityPasswordSettingsBinding // ViewBinding for settings screen
    private lateinit var sharedPrefs: SharedPreferences // Preferences store for vault settings
    private var passwordLength: Int = 16 // Generated password length (min 8)
    // Only store the 3 special character sets (last 3 of the 6 total sets)
    // First 3 sets (lowercase, uppercase, digits) are always enabled
    private var enabledSpecialSets = booleanArrayOf(true, true, true) // Toggles for 3 special sets

    override fun onCreate(savedInstanceState: Bundle?) { // Activity entry point
        super.onCreate(savedInstanceState)
        binding = ActivityPasswordSettingsBinding.inflate(layoutInflater) // Inflate binding
        setContentView(binding.root) // Attach layout

        sharedPrefs = getSharedPreferences("pqrypt_vault", Context.MODE_PRIVATE) // Shared prefs namespace
        loadSettings() // Read persisted values
        setupUI() // Wire listeners
        updateUI() // Reflect current state
    }

    private fun loadSettings() { // Load persisted preferences into memory
        passwordLength = sharedPrefs.getInt("password_length", 16) // Length slider value
        // Load only the special character sets (sets 4, 5, 6)
        enabledSpecialSets[0] = sharedPrefs.getBoolean("set_special1", true) // ~!@#$%^&*()
        enabledSpecialSets[1] = sharedPrefs.getBoolean("set_special2", true) // /.,';][=-
        enabledSpecialSets[2] = sharedPrefs.getBoolean("set_special3", true) // ><":}{+_
    }

    private fun saveSettings() { // Persist current settings to SharedPreferences
        sharedPrefs.edit().apply {
            putInt("password_length", passwordLength) // Store length
            // Save only the special character sets
            putBoolean("set_special1", enabledSpecialSets[0]) // Set 4
            putBoolean("set_special2", enabledSpecialSets[1]) // Set 5
            putBoolean("set_special3", enabledSpecialSets[2]) // Set 6
            apply() // Commit asynchronously
        }
    }

    private fun setupUI() { // Hook listeners for UI controls
        binding.btnBack.setOnClickListener { // Save and exit
            saveSettings() // Persist changes
            finish() // Close activity
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "password_settings"))
        }

        binding.seekBarLength.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener { // Length slider
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                passwordLength = progress + 8 // Minimum length of 8
                binding.tvLengthValue.text = passwordLength.toString() // Update label
            }

            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })

        binding.cbSet1.setOnCheckedChangeListener { _, isChecked ->
            enabledSpecialSets[0] = isChecked // Toggle set 4
        }

        binding.cbSet2.setOnCheckedChangeListener { _, isChecked ->
            enabledSpecialSets[1] = isChecked // Toggle set 5
        }

        binding.cbSet3.setOnCheckedChangeListener { _, isChecked ->
            enabledSpecialSets[2] = isChecked // Toggle set 6
        }
    }

    private fun updateUI() { // Reflect current settings on screen
        binding.seekBarLength.progress = passwordLength - 8 // Adjust for minimum of 8
        binding.tvLengthValue.text = passwordLength.toString() // Show current length
        binding.cbSet1.isChecked = enabledSpecialSets[0] // Set 4 toggle
        binding.cbSet2.isChecked = enabledSpecialSets[1] // Set 5 toggle
        binding.cbSet3.isChecked = enabledSpecialSets[2] // Set 6 toggle
    }
}
