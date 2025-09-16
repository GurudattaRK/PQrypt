package com.pqrypt.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.pqrypt.app.databinding.ActivityHelpBinding

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
                "Main Screen Guide",
                "Welcome to PQrypt! Here are your main options:\n\n" +
                "🟣 SECURE SHARE (Purple Button)\n" +
                "• What it does: Share files and text messages securely between devices\n" +
                "• When to use: When you want to send encrypted files or messages to another person\n" +
                "• Security: Uses post-quantum cryptography that's resistant to future quantum computers\n\n" +
                "🔴 FILE ENCRYPTION (Red Button)\n" +
                "• What it does: Encrypt individual files on your device\n" +
                "• When to use: When you want to protect files stored on your phone\n" +
                "• Security: Files are encrypted and can only be opened with the correct password\n\n" +
                "🟢 PQC KEY EXCHANGE (Green Button)\n" +
                "• What it does: Exchange cryptographic keys with another person\n" +
                "• When to use: When you need to establish secure communication keys\n" +
                "• Security: Uses quantum-resistant key exchange algorithms\n\n" +
                "🔵 PASSWORD GENERATOR (Blue Button)\n" +
                "• What it does: Generate strong, random passwords\n" +
                "• When to use: When you need secure passwords for accounts or encryption\n" +
                "• Security: Creates cryptographically secure random passwords\n\n" +
                "🟠 HELP BUTTON (Orange \"Help?\" Button)\n" +
                "• What it does: Opens help documentation for the app\n" +
                "• When to use: When you need guidance on using any feature\n\n" +
                "💡 TIP: All features use post-quantum cryptography for future-proof security against quantum computers!"
            )
            "file_encryption" -> Pair(
                "File Encryption Guide",
                "Protect files on your device with strong encryption:\n\n" +
                "📁 ENCRYPT TAB:\n" +
                "• Choose File Button: Select file to encrypt\n" +
                "• Password Field: Enter encryption password\n" +
                "• Encrypt Button: Start encryption process\n" +
                "• Progress Bar: Shows encryption progress\n\n" +
                "🔓 DECRYPT TAB:\n" +
                "• Choose File Button: Select encrypted file (.pqrypt2)\n" +
                "• Password Field: Enter decryption password\n" +
                "• Decrypt Button: Start decryption process\n" +
                "• Progress Bar: Shows decryption progress\n\n" +
                "📋 SCREEN ELEMENTS:\n" +
                "• File Display: Shows selected file name and size\n" +
                "• Status Messages: Shows success/error messages\n" +
                "• Output Location: Files are saved in Documents/PQrypt/\n\n" +
                "🔒 SECURITY TIPS:\n" +
                "• Use strong passwords and remember them - lost passwords mean lost files\n" +
                "• Encrypted files have .pqrypt2 extension\n" +
                "• Original files are kept safe during encryption\n" +
                "• Uses post-quantum cryptography for maximum security\n\n" +
                "📍 QUICK START:\n" +
                "1. Tap \"Choose File\" and select your file\n" +
                "2. Enter a strong password\n" +
                "3. Tap \"Encrypt\"\n" +
                "4. Find encrypted file in Documents/PQrypt/"
            )
            "password_vault" -> Pair(
                "Password Generator Guide",
                "Generate secure passwords for various uses:\n\n" +
                "📝 INPUT FIELDS:\n" +
                "• App/Website Name: Enter the service name (e.g., \"Gmail\", \"Facebook\")\n" +
                "• App Password: Optional additional password for extra security\n" +
                "• Master Password: Your main password that generates all others\n\n" +
                "🎯 GENERATE BUTTON:\n" +
                "• Creates a deterministic password\n" +
                "• Same inputs always produce the same password\n" +
                "• Cryptographically secure random generation\n\n" +
                "⚙️ SETTINGS BUTTON:\n" +
                "• Choose password length (8-128 characters)\n" +
                "• Select special character sets to include\n" +
                "• Lowercase, Uppercase and Numbers are always included\n\n" +
                "📋 PASSWORD DISPLAY:\n" +
                "• Shows generated password\n" +
                "• Copy button to copy to clipboard\n" +
                "• Strength indicator shows password security level\n\n" +
                "🔒 SECURITY FEATURES:\n" +
                "• Deterministic: Same inputs = same password\n" +
                "• No storage: Passwords generated on-demand\n" +
                "• Quantum-resistant algorithms\n" +
                "• Compatible with desktop version\n\n" +
                "💡 USAGE TIP:\n" +
                "Use the same Master Password across all your devices to get consistent passwords for each service!"
            )
            "password_settings" -> Pair(
                "Password Settings Guide",
                "Customize your password generation preferences:\n\n" +
                "📏 LENGTH SLIDER:\n" +
                "• Range: 8 to 128 characters\n" +
                "• Longer passwords = stronger security\n" +
                "• Recommended: 16+ characters for most uses\n\n" +
                "🔣 CHARACTER SETS:\n" +
                "• Special Set 1: ~!@#$%^&*()\n" +
                "• Special Set 2: /.,';][=-\n" +
                "• Special Set 3: ><\":}{+_\n\n" +
                "✅ ALWAYS INCLUDED:\n" +
                "• Lowercase letters (a-z)\n" +
                "• Uppercase letters (A-Z)\n" +
                "• Numbers (0-9)\n\n" +
                "⚙️ HOW TO USE:\n" +
                "1. Adjust length slider to desired password length\n" +
                "2. Check/uncheck special character sets as needed\n" +
                "3. Settings are automatically saved\n" +
                "4. Return to main screen to generate passwords\n\n" +
                "💡 RECOMMENDATIONS:\n" +
                "• For most websites: 16-20 characters with Set 1\n" +
                "• For high-security: 32+ characters with all sets\n" +
                "• For compatibility: Avoid Set 2 & 3 if site has restrictions\n\n" +
                "🔒 NOTE: These settings affect all future password generation and work across all your devices when using the same inputs."
            )
            "pqc_mode" -> Pair(
                "PQC Key Exchange Mode Guide",
                "Choose how to exchange quantum-resistant keys:\n\n" +
                "📡 MANUAL EXCHANGE:\n" +
                "• What it does: Step-by-step key exchange you control\n" +
                "• When to use: When you can't use Bluetooth or want more control\n" +
                "• How it works: Generate keys, exchange them manually (email/USB/etc.)\n" +
                "• Creates files: Generates .key files that you share manually\n\n" +
                "📶 BLUETOOTH EXCHANGE:\n" +
                "• What it does: Automatic key exchange via Bluetooth\n" +
                "• When to use: When both people are nearby (within Bluetooth range)\n" +
                "• How it works: Devices connect via Bluetooth, keys exchanged automatically\n" +
                "• No files: Everything happens automatically - no .key files created\n\n" +
                "👥 ROLES:\n" +
                "• Sender: Initiates the key exchange process\n" +
                "• Receiver: Responds to and completes the exchange\n\n" +
                "🔒 SECURITY:\n" +
                "• Uses post-quantum cryptography\n" +
                "• Resistant to future quantum computer attacks\n" +
                "• Perfect forward secrecy\n" +
                "• No intermediate key storage in Bluetooth mode\n\n" +
                "💡 NEXT STEPS:\n" +
                "• Choose Manual for remote key exchange\n" +
                "• Choose Bluetooth for local, automatic exchange\n" +
                "• Both methods provide the same security level"
            )
            "pqc_process" -> Pair(
                "PQC Manual Exchange Process",
                "Step-by-step guide for manual key exchange:\n\n" +
                "👤 SENDER PROCESS:\n" +
                "1️⃣ Generate 1.key\n" +
                "   • Creates initial key file to send to receiver\n" +
                "   • Share this file with receiver via secure channel\n\n" +
                "2️⃣ Process 2.key & Generate 3.key\n" +
                "   • Open 2.key file received from receiver\n" +
                "   • App automatically generates 3.key\n" +
                "   • Send 3.key to receiver\n\n" +
                "3️⃣ Final Key Generated\n" +
                "   • App creates final.key for encryption/decryption\n" +
                "   • Key exchange complete!\n\n" +
                "👤 RECEIVER PROCESS:\n" +
                "1️⃣ Process 1.key & Generate 2.key\n" +
                "   • Open 1.key file received from sender\n" +
                "   • App automatically generates 2.key\n" +
                "   • Send 2.key back to sender\n\n" +
                "2️⃣ Process 3.key\n" +
                "   • Open 3.key file received from sender\n" +
                "   • App automatically generates final.key\n" +
                "   • Key exchange complete!\n\n" +
                "📁 FILE LOCATIONS:\n" +
                "• All key files saved in Documents/PQrypt/\n" +
                "• Use \"Open Output Folder\" to find files\n\n" +
                "🔒 SECURITY TIPS:\n" +
                "• Use secure channels (encrypted email, secure messaging) to exchange .key files\n" +
                "• Verify file integrity before processing\n" +
                "• Clean up intermediate files after successful exchange"
            )
            "bluetooth" -> Pair(
                "Bluetooth Key Exchange Guide",
                "Automatic key exchange via Bluetooth connection:\n\n" +
                "📡 SENDER SETUP:\n" +
                "• Select \"Sender\" role\n" +
                "• Tap \"Make Discoverable\" to allow connections\n" +
                "• Wait for receiver to connect\n" +
                "• Device name will appear in connection list\n\n" +
                "📱 RECEIVER SETUP:\n" +
                "• Select \"Receiver\" role\n" +
                "• Tap \"Scan for Devices\" to find nearby devices\n" +
                "• Select sender's device from the list\n" +
                "• Connection will be established automatically\n\n" +
                "🔄 AUTOMATIC PROCESS:\n" +
                "• 1.key → 2.key → 3.key → final.key\n" +
                "• All steps happen automatically over Bluetooth\n" +
                "• Progress shown on both devices\n" +
                "• No manual file sharing required\n\n" +
                "📊 STATUS DISPLAY:\n" +
                "• Connection status and progress\n" +
                "• Current exchange step\n" +
                "• Success/error messages\n\n" +
                "🔒 SECURITY FEATURES:\n" +
                "• Encrypted Bluetooth communication\n" +
                "• Device verification before exchange\n" +
                "• No intermediate files stored\n" +
                "• Post-quantum cryptography\n\n" +
                "⚠️ TROUBLESHOOTING:\n" +
                "• Ensure Bluetooth is enabled on both devices\n" +
                "• Stay within Bluetooth range (typically 10 meters)\n" +
                "• Verify device names before connecting\n" +
                "• Grant all Bluetooth permissions when prompted"
            )
            else -> Pair(
                "Help",
                "Welcome to PQrypt Help!\n\n" +
                "This app provides quantum-resistant cryptography for:\n" +
                "• Secure file and text sharing\n" +
                "• File encryption and decryption\n" +
                "• Key exchange protocols\n" +
                "• Password generation\n\n" +
                "Use the Help button on any screen for specific guidance about that feature.\n\n" +
                "All features use post-quantum cryptography to protect against future quantum computer attacks."
            )
        }
    }
}
