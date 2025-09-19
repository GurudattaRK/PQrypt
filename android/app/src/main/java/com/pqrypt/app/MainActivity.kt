package com.pqrypt.app

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.pqrypt.app.databinding.ActivityMainBinding

//MARK: MainActivity
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Help button opens help screen
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "main"))
        }

        // Main feature buttons
        binding.btnFileEncryption.setOnClickListener {
            startActivity(Intent(this, FileEncryptionActivity::class.java))
        }

        binding.btnPqcKeyExchange.setOnClickListener {
            startActivity(Intent(this, KeyExchangeModeActivity::class.java))
        }

        binding.btnSecureShare.setOnClickListener {
            startActivity(Intent(this, SecureShareModeActivity::class.java))
        }

        binding.btnPasswordVault.setOnClickListener {
            startActivity(Intent(this, PasswordVaultActivity::class.java))
        }
    }
}