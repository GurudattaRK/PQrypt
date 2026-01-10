package com.pqrypt.app

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivitySecureShareModeBinding

class SecureShareModeActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareModeBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivitySecureShareModeBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
    }

    private fun setupUI() {
        binding.btnBack.setOnClickListener {
            finish()
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "secure_share"))
        }

        binding.btnContinue.setOnClickListener {
            val contentType = if (binding.rbText.isChecked) "text" else "file"
            val transferMode = when {
                binding.rbManual.isChecked -> "manual"
                binding.rbBluetooth.isChecked -> "bluetooth"
                else -> "wifi_direct"
            }
            val role = if (binding.rbSender.isChecked) "sender" else "receiver"

            if (transferMode == "wifi_direct" && contentType == "text") {
                Toast.makeText(this, "Wi‑Fi Direct is only available for file sharing", Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }

            val targetActivity = when (transferMode to contentType) {
                "manual" to "file" -> SecureShareManualFileActivity::class.java
                "bluetooth" to "file" -> SecureShareBluetoothFileActivity::class.java
                "wifi_direct" to "file" -> SecureShareWifiDirectFileActivity::class.java
                "manual" to "text" -> SecureShareManualTextActivity::class.java
                "bluetooth" to "text" -> SecureShareBluetoothTextActivity::class.java
                else -> SecureShareManualTextActivity::class.java
            }

            val intent = Intent(this, targetActivity).apply {
                putExtra("content_type", contentType)
                putExtra("transfer_mode", transferMode) 
                putExtra("role", role)
            }
            startActivity(intent)
        }
    }
}
