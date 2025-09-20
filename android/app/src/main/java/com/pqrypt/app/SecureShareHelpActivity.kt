package com.pqrypt.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import com.pqrypt.app.databinding.ActivitySecureShareHelpBinding

class SecureShareHelpActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivitySecureShareHelpBinding
    private lateinit var helpAdapter: HelpAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecureShareHelpBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        val screen = intent.getStringExtra("screen") ?: "general"
        
        setupUI(screen)
        setupRecyclerView(screen)
    }
    
    private fun setupUI(screen: String) {
        binding.tvTitle.text = when (screen) {
            "bluetooth_file" -> "Bluetooth File Sharing Help"
            "bluetooth_text" -> "Bluetooth Text Sharing Help"
            "manual_file" -> "Manual File Sharing Help"
            "manual_text" -> "Manual Text Sharing Help"
            else -> "Secure Share Help"
        }
        
        binding.btnBack.setOnClickListener {
            finish()
        }
    }
    
    private fun setupRecyclerView(screen: String) {
        val helpItems = getHelpItems(screen)
        helpAdapter = HelpAdapter(helpItems)
        
        binding.rvHelp.layoutManager = LinearLayoutManager(this)
        binding.rvHelp.adapter = helpAdapter
    }
    
    private fun getHelpItems(screen: String): List<HelpItem> {
        return when (screen) {
            "bluetooth_file" -> getBluetoothFileHelp()
            "bluetooth_text" -> getBluetoothTextHelp()
            "manual_file" -> getManualFileHelp()
            "manual_text" -> getManualTextHelp()
            else -> getGeneralHelp()
        }
    }
    
    private fun getBluetoothFileHelp(): List<HelpItem> {
        return listOf(
            HelpItem("Overview", "Bluetooth file sharing allows you to securely share encrypted files between devices using Bluetooth connection with quantum-resistant encryption."),
            
            HelpItem("Getting Started", "1. Choose your role: Sender or Receiver\n2. Bluetooth will be automatically enabled and configured\n3. Follow the steps below based on your role"),
            
            HelpItem("For Senders", "1. Select 'Sender' when prompted\n2. Tap 'Choose File' to select the file you want to encrypt and share\n3. The app will automatically generate encryption keys\n4. Tap 'Start Discovery' to find nearby devices\n5. Select the receiver's device from the list\n6. The file will be encrypted and sent automatically"),
            
            HelpItem("For Receivers", "1. Select 'Receiver' when prompted\n2. Tap 'Start Listening' to make your device discoverable\n3. Wait for the sender to connect and send the file\n4. The file will be automatically decrypted and saved\n5. Tap 'Open Output Folder' to view the received file"),
            
            HelpItem("File Storage", "All received files are saved to:\n/storage/emulated/0/Documents/pqrypt/\n\nUse the 'Open Output Folder' button to navigate directly to this location."),
            
            HelpItem("Security Features", "• Quantum-resistant encryption using lattice-based cryptography\n• Automatic key generation and exchange\n• Files are encrypted before transmission\n• Intermediate files are automatically cleaned up\n• Original file extensions are preserved after decryption"),
            
            HelpItem("Troubleshooting", "• Ensure both devices have Bluetooth enabled\n• Make sure devices are within Bluetooth range (typically 10 meters)\n• Grant all required permissions when prompted\n• If connection fails, try restarting the discovery process\n• Check that storage permissions are granted for file access")
        )
    }
    
    private fun getBluetoothTextHelp(): List<HelpItem> {
        return listOf(
            HelpItem("Overview", "Bluetooth text sharing allows you to securely share encrypted text messages between devices using Bluetooth connection with quantum-resistant encryption."),
            
            HelpItem("Getting Started", "1. Choose your role: Sender or Receiver\n2. Bluetooth will be automatically enabled and configured\n3. Follow the steps below based on your role"),
            
            HelpItem("For Senders", "1. Select 'Sender' when prompted\n2. Type your message in the text input field\n3. The app will automatically generate encryption keys as you type\n4. Tap 'Start Discovery' to find nearby devices\n5. Select the receiver's device from the list\n6. The text will be encrypted and sent automatically"),
            
            HelpItem("For Receivers", "1. Select 'Receiver' when prompted\n2. Tap 'Start Listening' to make your device discoverable\n3. Wait for the sender to connect and send the message\n4. The message will be automatically decrypted and displayed\n5. Tap 'Open Output Folder' to view saved message files"),
            
            HelpItem("Text Storage", "Decrypted messages are displayed on screen and also saved as text files to:\n/storage/emulated/0/Documents/pqrypt/\n\nUse the 'Open Output Folder' button to navigate to saved files."),
            
            HelpItem("Security Features", "• Quantum-resistant encryption using lattice-based cryptography\n• Automatic key generation and exchange\n• Text is encrypted before transmission\n• Intermediate files are automatically cleaned up\n• Character count is shown for sender convenience"),
            
            HelpItem("Troubleshooting", "• Ensure both devices have Bluetooth enabled\n• Make sure devices are within Bluetooth range (typically 10 meters)\n• Grant all required permissions when prompted\n• If connection fails, try restarting the discovery process\n• For long messages, consider using file sharing instead")
        )
    }
    
    private fun getManualFileHelp(): List<HelpItem> {
        return listOf(
            HelpItem("Overview", "Manual file sharing allows you to securely encrypt and share files through a step-by-step process that you control completely. Great for sharing via USB, email, or other manual methods."),
            
            HelpItem("Getting Started", "1. Choose your role: Sender or Receiver\n2. Follow the step-by-step process below\n3. You control each step of the key exchange and file transfer"),
            
            HelpItem("Sender Process", "Step 1: Generate 1.key\n• Tap 'Generate 1.key' to create the initial key file\n• Share this 1.key file with the receiver via your preferred method\n\nStep 2: Wait for 2.key\n• The receiver will send you back a 2.key file\n• Tap 'Open 2.key & Generate 3.key' to select the received 2.key\n• This automatically generates the final 3.key\n\nStep 3: Share 3.key\n• Send the generated 3.key back to the receiver\n\nStep 4: Encrypt & Share File\n• Select your file to encrypt\n• The file will be encrypted and ready to share\n• Send the encrypted file to the receiver"),
            
            HelpItem("Receiver Process", "Step 1: Wait for 1.key\n• Receive the 1.key file from the sender\n• Tap 'Open 1.key & Generate 2.key' to process it\n• This generates a 2.key file\n\nStep 2: Send 2.key Back\n• Share the generated 2.key with the sender\n\nStep 3: Wait for 3.key\n• Receive the 3.key from the sender\n• Tap 'Open 3.key & Generate Final Key' to process it\n\nStep 4: Decrypt File\n• Receive the encrypted file from sender\n• Tap 'Choose Encrypted File & Decrypt' to select and decrypt it\n• The decrypted file will be saved automatically"),
            
            HelpItem("File Storage", "All generated keys and decrypted files are saved to:\n/storage/emulated/0/Documents/pqrypt/\n\nUse the 'Open Output Folder' button to access these files for sharing or viewing."),
            
            HelpItem("Key Management", "• Each sharing session uses unique keys\n• Keys are automatically cleaned up after use\n• Never reuse keys for different files or sessions\n• The cleanup button removes intermediate files safely"),
            
            HelpItem("Security Best Practices", "• Always verify you're exchanging keys with the intended recipient\n• Use secure channels for key exchange when possible\n• Delete keys after successful file transfer\n• Keep encrypted files and keys separate during storage")
        )
    }
    
    private fun getManualTextHelp(): List<HelpItem> {
        return listOf(
            HelpItem("Overview", "Manual text sharing allows you to securely encrypt and share text messages through a step-by-step process. Perfect for sensitive messages that need to be shared via email, messaging apps, or other channels."),
            
            HelpItem("Getting Started", "1. Choose your role: Sender or Receiver\n2. Follow the step-by-step key exchange process\n3. You have complete control over each step"),
            
            HelpItem("Sender Process", "Step 1: Enter Text & Generate 1.key\n• Type your message in the text field\n• Tap 'Generate 1.key' to create the initial key file\n• Share this 1.key file with the receiver\n\nStep 2: Process 2.key\n• Receive the 2.key file from the receiver\n• Tap 'Open 2.key & Generate 3.key' to process it\n• This automatically generates the final 3.key\n\nStep 3: Share 3.key\n• Send the generated 3.key back to the receiver\n\nStep 4: Encrypt & Share Text\n• Tap 'Encrypt Text' to encrypt your message\n• Share the encrypted text file with the receiver"),
            
            HelpItem("Receiver Process", "Step 1: Process 1.key\n• Receive the 1.key file from the sender\n• Tap 'Open 1.key & Generate 2.key' to process it\n• Send the generated 2.key back to sender\n\nStep 2: Process 3.key\n• Receive the 3.key from the sender\n• Tap 'Open 3.key & Generate Final Key' to process it\n\nStep 3: Decrypt Message\n• Receive the encrypted text file from sender\n• Tap 'Choose Encrypted Text & Decrypt' to decrypt it\n• The decrypted message will be displayed on screen"),
            
            HelpItem("Text Storage", "• Decrypted messages are displayed on screen\n• Text files are also saved to /storage/emulated/0/Documents/pqrypt/\n• Use 'Open Output Folder' to access saved files\n• Character count is shown for convenience"),
            
            HelpItem("Key Management", "• Each text sharing session uses unique keys\n• Keys are automatically cleaned up after use\n• Never reuse keys for different messages\n• Use the cleanup button to remove intermediate files"),
            
            HelpItem("Security Tips", "• Verify recipient identity before sharing keys\n• Use different secure channels for keys and encrypted content\n• For very long messages, consider using file sharing instead\n• Clear the text input after encryption for additional security")
        )
    }
    
    private fun getGeneralHelp(): List<HelpItem> {
        return listOf(
            HelpItem("Secure Share Overview", "PQrypt's Secure Share feature provides quantum-resistant encryption for sharing files and text messages. Choose from Bluetooth or Manual sharing methods."),
            
            HelpItem("Sharing Methods", "• Bluetooth File Sharing: Direct device-to-device file transfer\n• Bluetooth Text Sharing: Direct messaging between devices\n• Manual File Sharing: Step-by-step file encryption for any transfer method\n• Manual Text Sharing: Step-by-step text encryption for any messaging platform"),
            
            HelpItem("Security Technology", "All sharing methods use lattice-based cryptography, which is resistant to both classical and quantum computer attacks, ensuring your data remains secure in the future."),
            
            HelpItem("Getting Help", "Each sharing method has its own detailed help guide. Access help by tapping the help button (?) in any secure share screen.")
        )
    }
}

data class HelpItem(
    val title: String,
    val content: String
)

class HelpAdapter(private val helpItems: List<HelpItem>) : RecyclerView.Adapter<HelpAdapter.HelpViewHolder>() {
    
    class HelpViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val titleText: TextView = itemView.findViewById(R.id.tvHelpTitle)
        val contentText: TextView = itemView.findViewById(R.id.tvHelpContent)
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): HelpViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_help, parent, false)
        return HelpViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: HelpViewHolder, position: Int) {
        val helpItem = helpItems[position]
        holder.titleText.text = helpItem.title
        holder.contentText.text = helpItem.content
    }
    
    override fun getItemCount(): Int = helpItems.size
}
