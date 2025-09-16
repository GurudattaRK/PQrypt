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
                "Encrypt files through a step-by-step process you control:\n\n" +
                "📤 SENDER PROCESS:\n" +
                "1️⃣ Generate 1.key\n" +
                "   • Creates initial key file to send to receiver\n" +
                "   • Share this file with receiver via secure channel (email/USB/etc.)\n\n" +
                "2️⃣ Open 2.key & Generate 3.key\n" +
                "   • Process receiver's 2.key file\n" +
                "   • App automatically creates final 3.key\n" +
                "   • Select your file and encrypt it\n\n" +
                "3️⃣ Share Files\n" +
                "   • Send the 3.key and encrypted file to receiver\n" +
                "   • Use secure channels for file transfer\n\n" +
                "📥 RECEIVER PROCESS:\n" +
                "1️⃣ Open 1.key & Generate 2.key\n" +
                "   • Process sender's 1.key file\n" +
                "   • App automatically creates 2.key to send back\n" +
                "   • Share 2.key with sender\n\n" +
                "2️⃣ Open 3.key & Generate Final Key\n" +
                "   • Process sender's 3.key file\n" +
                "   • App creates decryption key automatically\n\n" +
                "3️⃣ Choose Encrypted File & Decrypt\n" +
                "   • Select the received encrypted file\n" +
                "   • File is automatically decrypted\n\n" +
                "🎯 SCREEN ELEMENTS:\n" +
                "• Sender/Receiver Toggle: Choose your role in the exchange\n" +
                "• Step-by-step buttons: Follow numbered steps (1.key → 2.key → 3.key → encrypt/decrypt)\n" +
                "• File Selection: Choose files to encrypt or decrypt\n" +
                "• Progress Display: Shows which step you're currently on\n" +
                "• Cleanup Button: Removes intermediate .key files after successful transfer\n\n" +
                "📁 FILE LOCATIONS:\n" +
                "• All files saved in Documents/PQrypt/\n" +
                "• Use \"Open Output Folder\" to find your files\n\n" +
                "🔒 SECURITY TIPS:\n" +
                "• Use secure channels (encrypted email, secure messaging) to exchange .key files\n" +
                "• Creates .key files and .encrypted files that you share manually\n" +
                "• When you can't use Bluetooth or want more control over the process"
            )
            "manual_text" -> Pair(
                "Manual Text Sharing Guide",
                "Encrypt text messages through a step-by-step process:\n\n" +
                "📤 SENDER PROCESS:\n" +
                "1️⃣ Enter Text & Generate 1.key\n" +
                "   • Type your message in the text field\n" +
                "   • Generate 1.key file to send to receiver\n" +
                "   • Share 1.key with receiver via secure channel\n\n" +
                "2️⃣ Open 2.key & Generate 3.key\n" +
                "   • Process receiver's 2.key file\n" +
                "   • App automatically generates 3.key and encrypts your text\n" +
                "   • Creates encrypted text file\n\n" +
                "3️⃣ Share Files\n" +
                "   • Send 3.key and encrypted text file to receiver\n" +
                "   • Use secure channels for file transfer\n\n" +
                "📥 RECEIVER PROCESS:\n" +
                "1️⃣ Open 1.key & Generate 2.key\n" +
                "   • Process sender's 1.key file\n" +
                "   • App automatically creates 2.key to send back\n" +
                "   • Share 2.key with sender\n\n" +
                "2️⃣ Open 3.key & Generate Final Key\n" +
                "   • Process sender's 3.key file\n" +
                "   • App creates decryption key automatically\n\n" +
                "3️⃣ Open Encrypted Text & Decrypt\n" +
                "   • Select the encrypted text file\n" +
                "   • Message is automatically decrypted and displayed\n\n" +
                "🎯 SCREEN ELEMENTS:\n" +
                "• Text Input Field (Sender): Type your message\n" +
                "• Character Counter: Shows message length\n" +
                "• Step-by-step Process: Same 1.key → 2.key → 3.key process as file sharing\n" +
                "• Encrypt Text Button: Encrypts your typed message\n" +
                "• Decrypt Display: Shows decrypted message after successful decryption\n" +
                "• Cleanup Button: Removes intermediate files\n\n" +
                "📁 FILE MANAGEMENT:\n" +
                "• Creates .key files and encrypted text files\n" +
                "• All files saved in Documents/PQrypt/\n" +
                "• Same key exchange as file sharing, but for text messages\n\n" +
                "💡 WHEN TO USE:\n" +
                "• For secure text sharing when Bluetooth isn't available\n" +
                "• When you want more control over the encryption process\n" +
                "• For sharing sensitive messages via email or other channels"
            )
            "bluetooth_file" -> Pair(
                "Bluetooth File Sharing Guide",
                "Share encrypted files directly between devices via Bluetooth:\n\n" +
                "📡 HOW IT WORKS:\n" +
                "• Both devices connect via Bluetooth\n" +
                "• Keys are exchanged automatically\n" +
                "• File is encrypted and transferred\n" +
                "• No intermediate files created\n" +
                "• Everything happens automatically\n\n" +
                "📤 SENDER SETUP:\n" +
                "• Select \"Sender\" role\n" +
                "• Tap \"Choose File\" and select your file\n" +
                "• Tap \"Discover Devices\" to find nearby devices\n" +
                "• Select receiver's device from the list\n" +
                "• File is automatically encrypted and sent\n\n" +
                "📥 RECEIVER SETUP:\n" +
                "• Select \"Receiver\" role\n" +
                "• Tap \"Start Listening\" to make device discoverable\n" +
                "• Wait for sender to connect\n" +
                "• File is automatically received and decrypted\n" +
                "• Tap \"Open Output Folder\" to find your file\n\n" +
                "🎯 SCREEN ELEMENTS:\n" +
                "• Sender/Receiver Toggle: Choose whether you're sending or receiving\n" +
                "• Choose File Button (Sender only): Select the file to encrypt and send\n" +
                "• Discover Devices Button (Sender): Find nearby devices to connect to\n" +
                "• Start Listening Button (Receiver): Make device discoverable\n" +
                "• Device List: Shows available devices to connect to\n" +
                "• Open Output Folder Button (Receiver): Opens Documents/PQrypt/\n" +
                "• Status Display: Shows connection status and transfer progress\n\n" +
                "💡 WHEN TO USE:\n" +
                "• When both people are nearby (within Bluetooth range)\n" +
                "• For quick, automatic file sharing\n" +
                "• When you want seamless encryption without manual steps\n\n" +
                "⚠️ TROUBLESHOOTING:\n" +
                "• Ensure Bluetooth is enabled on both devices\n" +
                "• Grant all requested permissions\n" +
                "• Stay within Bluetooth range during transfer\n" +
                "• Verify device names before connecting"
            )
            "bluetooth_text" -> Pair(
                "Bluetooth Text Sharing Guide",
                "Share encrypted text messages directly between devices via Bluetooth:\n\n" +
                "📡 HOW IT WORKS:\n" +
                "• Type message, connect via Bluetooth\n" +
                "• Message is encrypted and transferred automatically\n" +
                "• No intermediate files created\n" +
                "• Text displayed directly on receiver's screen\n\n" +
                "📤 SENDER SETUP:\n" +
                "• Select \"Sender\" role\n" +
                "• Type your message in the text input field\n" +
                "• Tap \"Discover Devices\" to find nearby devices\n" +
                "• Select receiver's device from the list\n" +
                "• Message is automatically encrypted and sent\n\n" +
                "📥 RECEIVER SETUP:\n" +
                "• Select \"Receiver\" role\n" +
                "• Tap \"Start Listening\" to make device discoverable\n" +
                "• Wait for sender to connect\n" +
                "• Decrypted message appears on screen automatically\n\n" +
                "🎯 SCREEN ELEMENTS:\n" +
                "• Sender/Receiver Toggle: Choose whether you're sending or receiving text\n" +
                "• Text Input Field (Sender only): Type your message here\n" +
                "• Character Counter: Shows how many characters you've typed\n" +
                "• Discover Devices Button (Sender): Find nearby devices to connect to\n" +
                "• Start Listening Button (Receiver): Make device discoverable\n" +
                "• Device List: Shows available devices to connect to\n" +
                "• Received Text Display (Receiver): Shows decrypted message after transfer\n" +
                "• Status Display: Shows connection status and transfer progress\n\n" +
                "💡 WHEN TO USE:\n" +
                "• For secure messaging when both people are nearby\n" +
                "• Quick encrypted text sharing without files\n" +
                "• When you want instant, automatic encryption\n\n" +
                "🔒 SECURITY FEATURES:\n" +
                "• Post-quantum cryptography\n" +
                "• No message storage on devices\n" +
                "• Encrypted Bluetooth communication\n" +
                "• Automatic key exchange and cleanup"
            )
            else -> Pair(
                "Secure Share Overview",
                "Share files and text messages securely between devices:\n\n" +
                "🔄 SHARING MODES:\n\n" +
                "📶 BLUETOOTH SHARING:\n" +
                "• What it does: Share encrypted files/text directly via Bluetooth\n" +
                "• When to use: When both people are nearby (within Bluetooth range)\n" +
                "• How it works: Automatic connection, key exchange, and transfer\n" +
                "• No intermediate files: Everything happens automatically\n\n" +
                "📧 MANUAL SHARING:\n" +
                "• What it does: Encrypt files/text through step-by-step process\n" +
                "• When to use: When you can't use Bluetooth or want more control\n" +
                "• How it works: Generate keys, exchange manually (email/USB/etc.)\n" +
                "• Creates files: Generates .key files and .encrypted files to share\n\n" +
                "📁 FILE VS TEXT:\n" +
                "• File Sharing: Encrypt and share any file securely\n" +
                "• Text Sharing: Encrypt and share text messages securely\n\n" +
                "🔒 SECURITY FEATURES:\n" +
                "• Uses post-quantum cryptography for future-proof security\n" +
                "• Resistant to quantum computer attacks\n" +
                "• Perfect forward secrecy\n" +
                "• No permanent key storage in Bluetooth mode\n\n" +
                "💡 QUICK START:\n" +
                "• Choose Bluetooth for nearby, automatic sharing\n" +
                "• Choose Manual for remote sharing with full control\n" +
                "• Both methods provide the same security level\n\n" +
                "📍 NEXT STEPS:\n" +
                "Select your preferred sharing method from the main Secure Share screen to get detailed guidance for that specific feature."
            )
        }
    }
}
