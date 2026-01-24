package com.pqrypt.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivityHelpBinding

class SecureShareHelpActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityHelpBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHelpBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        binding.btnBack.setOnClickListener { finish() }
        
        val screen = intent.getStringExtra("screen") ?: "general"
        val (title, content) = helpContentFor(screen)
        binding.tvTitle.text = title
        binding.tvContent.text = content
    }
    
    private fun helpContentFor(screen: String): Pair<String, String> {
        return when (screen) {
            "manual_file" -> Pair(
                "Manual File Sharing Guide",
                "Use this when you want to share a file but you cannot use Bluetooth or Wi‑Fi Direct.\n\n" +
                "Sender (the person sending the file):\n" +
                "1) Generate 1.key\n" +
                "2) Send 1.key to the receiver\n" +
                "3) Open 2.key from the receiver\n" +
                "4) Choose the file and encrypt\n" +
                "5) Send the encrypted file (.pqrypt) to the receiver\n\n" +
                "Receiver (the person receiving the file):\n" +
                "1) Open 1.key from the sender\n" +
                "2) Share 2.key back to the sender\n" +
                "3) When you get the encrypted file (.pqrypt), open it to decrypt\n" +
                "   • If the app asks for 3.key first, open 3.key and then open the encrypted file\n\n" +
                "Important notes:\n" +
                "• The encrypted file usually contains everything needed for decryption.\n" +
                "• The sender may also send a file named 3.key (keep it until the file decrypts).\n" +
                "• After a successful decrypt, the app may try to delete the key files and encrypted file." 
            )
            "manual_text" -> Pair(
                "Manual Text Sharing Guide",
                "Use this to share a text message when you cannot use Bluetooth.\n\n" +
                "Sender (the person sending the message):\n" +
                "1) Type your message\n" +
                "2) Generate 1.key\n" +
                "3) Send 1.key to the receiver\n" +
                "4) Open 2.key from the receiver\n" +
                "5) The app creates one encrypted file: text.pqrypt\n" +
                "6) Send text.pqrypt to the receiver\n\n" +
                "Receiver (the person receiving the message):\n" +
                "1) Open 1.key from the sender\n" +
                "2) Send 2.key back to the sender\n" +
                "3) When you get text.pqrypt, open it\n" +
                "4) The decrypted text will show on screen\n\n" +
                "Important notes:\n" +
                "• You only need to send ONE encrypted file (text.pqrypt).\n" +
                "• After a successful decrypt, the app may try to delete the key files and encrypted file." 
            )
            "bluetooth_file" -> Pair(
                "Bluetooth File Sharing Guide",
                "Use this when both people are nearby. The app handles the secure connection automatically.\n\n" +
                "Sender:\n" +
                "1) Choose Sender\n" +
                "2) Choose the file\n" +
                "3) Discover devices and select the receiver\n\n" +
                "Receiver:\n" +
                "1) Choose Receiver\n" +
                "2) Start listening\n" +
                "3) Wait for the sender to connect\n\n" +
                "The file is encrypted before it is sent and decrypted after it is received." 
            )
            "bluetooth_text" -> Pair(
                "Bluetooth Text Sharing Guide",
                "Use this when both people are nearby. The message is encrypted before it is sent.\n\n" +
                "Sender:\n" +
                "1) Choose Sender\n" +
                "2) Type your message\n" +
                "3) Discover devices and select the receiver\n\n" +
                "Receiver:\n" +
                "1) Choose Receiver\n" +
                "2) Start listening\n" +
                "3) Wait for the sender to connect\n\n" +
                "The decrypted message appears on the receiver screen." 
            )
            "wifi_direct_file" -> Pair(
                "Wi‑Fi Direct File Sharing Guide",
                "Use this when you are nearby but Bluetooth is not ideal.\n\n" +
                "Sender:\n" +
                "1) Choose Sender\n" +
                "2) Choose the file\n" +
                "3) Discover devices and select the receiver\n\n" +
                "Receiver:\n" +
                "1) Choose Receiver\n" +
                "2) Start listening\n" +
                "3) Wait for the sender to connect\n\n" +
                "The file is encrypted before transfer and decrypted after receiving." 
            )
            else -> Pair(
                "Secure Share Overview",
                "Secure Share lets you send a file or message safely.\n\n" +
                "Choose a transfer method:\n" +
                "• Bluetooth: nearby and automatic\n" +
                "• Wi‑Fi Direct: nearby and automatic (file only)\n" +
                "• Manual: works even when you are not nearby (you send small files back and forth)\n\n" +
                "Manual sharing uses small files named 1.key and 2.key, plus one encrypted .pqrypt file." 
            )
        }
    }
}
