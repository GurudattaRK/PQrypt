package com.pqrypt.app

import android.content.Intent
import android.os.Bundle
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
            val transferMode = if (binding.rbManual.isChecked) "manual" else "bluetooth"
            val role = if (binding.rbSender.isChecked) "sender" else "receiver"

            val targetActivity = when (transferMode to contentType) {
                "manual" to "file" -> SecureShareManualFileActivity::class.java
                "bluetooth" to "file" -> SecureShareBluetoothFileActivity::class.java
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
