package com.pineapple.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.pineapple.app.databinding.ActivityHelpBinding

class HelpActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHelpBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHelpBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }

        val screen = intent.getStringExtra("screen") ?: "main"
        val (title, content) = helpContentFor(screen)
        binding.tvTitle.text = title
        binding.tvContent.text = content
    }

    private fun helpContentFor(screen: String): Pair<String, String> {
        return when (screen) {
            "main" -> Pair(
                "Welcome to PQrypt",
                "• File Encryption: Encrypt/Decrypt files using a password or a key file.\n\n" +
                "• PQC Key Exchange: Exchange post-quantum key files (1.key → 2.key → 3.key → final.key).\n\n" +
                "• Password Generator: Deterministically generate strong passwords that match the desktop app."
            )
            "file_encryption" -> Pair(
                "File Encryption Help",
                "• Choose File: Select the file to encrypt or decrypt.\n\n" +
                "• Password or Key File: Use either a password or a key file (not both).\n\n" +
                "• Encrypt (green): Produces <filename>.encrypted with a PQRYPT header.\n\n" +
                "• Decrypt (red): Restores the original file from a .encrypted file."
            )
            "password_vault" -> Pair(
                "Password Generator Help",
                "• Enter App/Website name, optional App Password, and Master Password.\n\n" +
                "• Generate Password (green): Creates a deterministic password.\n\n" +
                "• Settings: Choose length and special sets. Lowercase, Uppercase and Numbers are always included."
            )
            "password_settings" -> Pair(
                "Password Settings Help",
                "• Length slider: 8 to 64 characters.\n\n" +
                "• Special Set 1: ~!@#$%^&*()\n" +
                "• Special Set 2: /.,';][=-\n" +
                "• Special Set 3: ><\":}{+_\n\n" +
                "• Lowercase (a-z), Uppercase (A-Z) and Numbers (0-9) are always included."
            )
            "pqc_mode" -> Pair(
                "PQC Key Exchange Help",
                "• Sender: Start exchange and create 1.key, send 1.key to Receiver.\n\n" +
                "• Receiver: Open 1.key → generate 2.key → send 2.key to Sender."
            )
            "pqc_process" -> Pair(
                "PQC Exchange Steps",
                "Sender:\n" +
                "  1) Generate 1.key → send 1.key to Receiver.\n" +
                "  2) Open 2.key → generate 3.key → send 3.key to Receiver.\n\n" +
                "Receiver:\n" +
                "  1) Open 1.key → generate 2.key → send 2.key to Sender.\n" +
                "  2) Open 3.key → app saves final.key."
            )
            "bluetooth" -> Pair(
                "Bluetooth Key Exchange",
                "• Sender: Make device discoverable, wait for connection.\n\n" +
                "• Receiver: Scan and connect to Sender.\n\n" +
                "• Follow on-screen steps: 1.key → 2.key → 3.key → final.key."
            )
            else -> Pair(
                "Help",
                "No additional information."
            )
        }
    }
}
