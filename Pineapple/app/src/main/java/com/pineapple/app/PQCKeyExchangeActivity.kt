package com.pineapple.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.pineapple.app.databinding.ActivityPqcKeyExchangeBinding

class PQCKeyExchangeActivity : AppCompatActivity() { // Entry screen to choose Sender or Receiver role for PQC key exchange

    private lateinit var binding: ActivityPqcKeyExchangeBinding // ViewBinding for activity_pqc_key_exchange.xml

    override fun onCreate(savedInstanceState: Bundle?) { // Activity lifecycle entry point
        super.onCreate(savedInstanceState)
        binding = ActivityPqcKeyExchangeBinding.inflate(layoutInflater) // Inflate binding for this layout
        setContentView(binding.root) // Attach root view

        setupUI() // Wire up click handlers
    }

    private fun setupUI() { // Initialize UI interactions
        binding.btnBack.setOnClickListener { // Navigate back to previous screen
            finish() // Close this activity
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "pqc_mode"))
        }

        binding.btnSender.setOnClickListener { // Start key exchange as Sender
            val intent = Intent(this, KeyExchangeProcessActivity::class.java) // Launch process screen
            intent.putExtra("is_sender", true) // Pass role flag
            startActivity(intent) // Navigate
        }

        binding.btnReceiver.setOnClickListener { // Start key exchange as Receiver
            val intent = Intent(this, KeyExchangeProcessActivity::class.java) // Launch process screen
            intent.putExtra("is_sender", false) // Pass role flag
            startActivity(intent) // Navigate
        }
    }
}
