package com.pqrypt.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivityKeyExchangeModeBinding

class KeyExchangeModeActivity : AppCompatActivity() {

    private lateinit var binding: ActivityKeyExchangeModeBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityKeyExchangeModeBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
    }

    private fun setupUI() {
        binding.btnBack.setOnClickListener {
            finish()
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "pqc_mode"))
        }

        binding.btnManualMode.setOnClickListener {
            val intent = Intent(this, PQCKeyExchangeActivity::class.java)
            startActivity(intent)
        }

        binding.btnBluetoothMode.setOnClickListener {
            val intent = Intent(this, BluetoothKeyExchangeActivity::class.java)
            startActivity(intent)
        }
    }
    
}
