package com.pqrypt.app

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.pqrypt.app.databinding.ActivitySecureShareBluetoothTextBinding
import kotlinx.coroutines.*
import android.os.ParcelFileDescriptor
import java.io.*
import java.util.*

class SecureShareBluetoothTextActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareBluetoothTextBinding
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var deviceAdapter: BluetoothDeviceAdapter? = null
    private val discoveredDevices = mutableListOf<BluetoothDevice>()
    
    private var contentType = "text"
    private var transferMode = "bluetooth"
    private var role = "sender"
    private var isSender = true
    
    // Text and connectivity state
    private var inputText = ""
    private var tempTextFile: File? = null
    private var selectedDevice: BluetoothDevice? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var serverSocket: BluetoothServerSocket? = null
    
    // PQC Key exchange data
    private var senderState: Any? = null
    private var receiverState: Any? = null
    private var finalSharedSecret: ByteArray? = null
    
    companion object {
        private const val UUID_STRING = "8ce255c0-223a-11e0-ac64-0800200c9a66"
        private val MY_UUID = UUID.fromString(UUID_STRING)
        private const val REQUEST_ENABLE_BT = 1
        private const val REQUEST_DISCOVERABLE_BT = 2
        private const val PERMISSIONS_REQUEST_CODE = 100
    }

    private val bluetoothReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device: BluetoothDevice? = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    device?.let {
                        if (!discoveredDevices.contains(it)) {
                            discoveredDevices.add(it)
                            deviceAdapter?.notifyDataSetChanged()
                        }
                    }
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    binding.tvStatus.text = "Discovery finished. Select a device to connect."
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecureShareBluetoothTextBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Get intent extras
        contentType = intent.getStringExtra("content_type") ?: "text"
        transferMode = intent.getStringExtra("transfer_mode") ?: "bluetooth"
        role = intent.getStringExtra("role") ?: "sender"
        isSender = role == "sender"

        setupUI()
        checkPermissions()  // Check permissions before setting up Bluetooth
        updateUI()
    }

    private fun setupUI() {
        binding.tvRole.text = "Role: ${role.capitalize()}"
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "secure_share"))
        }

        // Text input character counter and auto-key generation
        binding.etTextInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                inputText = s?.toString() ?: ""
                binding.tvCharCount.text = "${inputText.length} characters"
                updateUI()
                
                // Auto-generate keys when text is entered (for sender)
                if (isSender && inputText.trim().isNotEmpty()) {
                    autoGenerateInitialKeys()
                }
            }
        })

        // Bluetooth setup
        binding.btnSetupBluetooth.setOnClickListener {
            setupBluetooth()
        }

        // Discover/Connect button
        binding.btnDiscoverConnect.setOnClickListener {
            if (isSender) {
                startDiscovery()
            } else {
                startListening()
            }
        }

        // Setup RecyclerView for device list (sender only)
        if (isSender) {
            deviceAdapter = BluetoothDeviceAdapter(discoveredDevices) { device ->
                selectedDevice = device
                connectToDevice(device)
            }
            binding.rvDevices.layoutManager = LinearLayoutManager(this)
            binding.rvDevices.adapter = deviceAdapter
        }
    }

    private fun setupBluetooth() {
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null) {
            showError("Bluetooth not supported on this device")
            return
        }

        if (!bluetoothAdapter!!.isEnabled) {
            val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT)
        } else {
            checkPermissions()
        }
    }

    private fun checkPermissions() {
        val permissions = mutableListOf<String>()
        
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), PERMISSIONS_REQUEST_CODE)
        } else {
            onPermissionsGranted()
        }
    }

    private fun onPermissionsGranted() {
        // Setup Bluetooth after permissions are granted
        setupBluetooth()
        
        binding.btnDiscoverConnect.isEnabled = true
        binding.tvStatus.text = if (isSender) "Ready to discover devices" else "Ready to listen for connections"
        
        // Register Bluetooth receiver
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        registerReceiver(bluetoothReceiver, filter)
    }

    private fun updateUI() {
        // Show/hide UI elements based on role
        binding.llTextInput.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.llTextDisplay.visibility = if (!isSender) View.VISIBLE else View.GONE
        binding.rvDevices.visibility = if (isSender) View.VISIBLE else View.GONE
        
        // Update button texts
        binding.btnDiscoverConnect.text = if (isSender) "Discover Devices" else "Listen for Connection"
        
        // Enable discover/connect based on readiness
        if (isSender) {
            binding.btnDiscoverConnect.isEnabled = inputText.trim().isNotEmpty() && bluetoothAdapter?.isEnabled == true
        }
    }

    private fun autoGenerateInitialKeys() {
        if (!isSender || inputText.trim().isEmpty()) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Create temporary text file
                createTempTextFile()
                
                val result = RustyCrypto.pqc4HybridInit()
                if (result != null && result.isNotEmpty()) {
                    // Store sender state for later use
                    withContext(Dispatchers.Main) {
                        binding.tvStatus.text = "Keys auto-generated. Ready to connect via Bluetooth."
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Key generation failed: ${e.message}")
                }
            }
        }
    }

    private fun startDiscovery() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        discoveredDevices.clear()
        deviceAdapter?.notifyDataSetChanged()
        
        if (bluetoothAdapter?.isDiscovering == true) {
            bluetoothAdapter?.cancelDiscovery()
        }
        
        bluetoothAdapter?.startDiscovery()
        binding.tvStatus.text = "Discovering devices..."
        binding.rvDevices.visibility = View.VISIBLE
    }

    private fun startListening() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                serverSocket = bluetoothAdapter?.listenUsingRfcommWithServiceRecord("PQryptSecureTextShare", MY_UUID)
                
                withContext(Dispatchers.Main) {
                    binding.tvConnectionStatus.text = "Listening for connections..."
                    binding.tvStatus.text = "Make yourself discoverable and wait for sender to connect"
                    
                    // Make device discoverable
                    val discoverableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                        putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300)
                    }
                    startActivityForResult(discoverableIntent, REQUEST_DISCOVERABLE_BT)
                }

                // Accept incoming connection
                val socket = serverSocket?.accept()
                socket?.let {
                    withContext(Dispatchers.Main) {
                        bluetoothSocket = it
                        binding.tvConnectionStatus.text = "Connected to ${it.remoteDevice.name}"
                        startKeyExchangeAsReceiver()
                    }
                }
            } catch (e: IOException) {
                withContext(Dispatchers.Main) {
                    showError("Failed to start listening: ${e.message}")
                }
            }
        }
    }

    private fun connectToDevice(device: BluetoothDevice) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                if (ActivityCompat.checkSelfPermission(this@SecureShareBluetoothTextActivity, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                    return@launch
                }

                bluetoothAdapter?.cancelDiscovery()
                
                val socket = device.createRfcommSocketToServiceRecord(MY_UUID)
                socket.connect()
                
                withContext(Dispatchers.Main) {
                    bluetoothSocket = socket
                    binding.tvConnectionStatus.text = "Connected to ${device.name}"
                    startKeyExchangeAsSender()
                }
            } catch (e: IOException) {
                withContext(Dispatchers.Main) {
                    showError("Failed to connect: ${e.message}")
                }
            }
        }
    }

    private fun startKeyExchangeAsSender() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Perform full key exchange and text transfer
                performSenderFlow()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Sender flow failed: ${e.message}")
                }
            }
        }
    }

    private fun startKeyExchangeAsReceiver() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Perform full key exchange and text reception
                performReceiverFlow()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Receiver flow failed: ${e.message}")
                }
            }
        }
    }

    private suspend fun performSenderFlow() {
        withContext(Dispatchers.Main) {
            binding.llProgress.visibility = View.VISIBLE
            binding.tvProgressTitle.text = "Performing Key Exchange..."
            binding.progressBar.progress = 10
        }

        // Step 1: Send initial key
        val initResult = RustyCrypto.pqc4HybridInit()
        senderState = initResult[1]
        val initialKey = initResult[0] as ByteArray
        sendBluetoothData(initialKey)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 30
        }

        // Step 2: Receive response key
        val responseKey = receiveBluetoothData()
        val finalResult = RustyCrypto.pqc4HybridSndFinal(responseKey, senderState as ByteArray)
        
        // Step 3: Send final key
        val finalKey = finalResult[1] as ByteArray
        sendBluetoothData(finalKey)
        finalSharedSecret = finalResult[0] as ByteArray
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Encrypting and Sending Text..."
        }

        // Step 4: Encrypt and send text
        val encryptedTextData = encryptInputText()
        sendBluetoothText(encryptedTextData)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            showSuccess("Text encrypted and sent successfully!")
        }
    }

    private suspend fun performReceiverFlow() {
        withContext(Dispatchers.Main) {
            binding.llProgress.visibility = View.VISIBLE
            binding.tvProgressTitle.text = "Performing Key Exchange..."
            binding.progressBar.progress = 10
        }

        // Step 1: Receive initial key
        val initialKey = receiveBluetoothData()
        val recvResult = RustyCrypto.pqc4HybridRecv(initialKey)
        
        // Step 2: Send response key
        val responseKey = recvResult[0] as ByteArray
        receiverState = recvResult[1]
        sendBluetoothData(responseKey)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 40
        }

        // Step 3: Receive final key and generate shared secret
        val finalKey = receiveBluetoothData()
        finalSharedSecret = RustyCrypto.pqc4HybridRecvFinal(finalKey, receiverState as ByteArray)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Receiving and Decrypting Text..."
        }

        // Step 4: Receive and decrypt text
        val encryptedTextData = receiveBluetoothText()
        val decryptedText = decryptReceivedText(encryptedTextData)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            binding.tvReceivedText.text = decryptedText
            showSuccess("Text received and decrypted successfully!")
        }
    }

    private fun sendBluetoothData(data: ByteArray?) {
        data?.let {
            bluetoothSocket?.outputStream?.write(it)
            bluetoothSocket?.outputStream?.flush()
        }
    }

    private fun receiveBluetoothData(): ByteArray {
        val buffer = ByteArray(8192)
        val bytesRead = bluetoothSocket?.inputStream?.read(buffer) ?: 0
        return buffer.copyOf(bytesRead)
    }

    private fun sendBluetoothText(textData: ByteArray) {
        // Send text size first
        val sizeBytes = ByteArray(4)
        sizeBytes[0] = (textData.size shr 24).toByte()
        sizeBytes[1] = (textData.size shr 16).toByte()
        sizeBytes[2] = (textData.size shr 8).toByte()
        sizeBytes[3] = textData.size.toByte()
        
        bluetoothSocket?.outputStream?.write(sizeBytes)
        bluetoothSocket?.outputStream?.write(textData)
        bluetoothSocket?.outputStream?.flush()
    }

    private fun receiveBluetoothText(): ByteArray {
        // Read text size first
        val sizeBuffer = ByteArray(4)
        bluetoothSocket?.inputStream?.read(sizeBuffer)
        val textSize = ((sizeBuffer[0].toInt() and 0xFF) shl 24) or
                      ((sizeBuffer[1].toInt() and 0xFF) shl 16) or
                      ((sizeBuffer[2].toInt() and 0xFF) shl 8) or
                      (sizeBuffer[3].toInt() and 0xFF)
        
        // Read text data
        val textData = ByteArray(textSize)
        var totalRead = 0
        while (totalRead < textSize) {
            val bytesRead = bluetoothSocket?.inputStream?.read(textData, totalRead, textSize - totalRead) ?: 0
            totalRead += bytesRead
        }
        
        return textData
    }

    private fun encryptInputText(): ByteArray {
        return try {
            // Update temp text file with current input
            createTempTextFile()
            
            val inputPath = tempTextFile!!.absolutePath
            val outputPath = "${inputPath}.encrypted"
            
            // Open file descriptors for real encryption
            val inputFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
            val outputFd = ParcelFileDescriptor.open(File(outputPath), ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
            
            val success = try {
                // Use real triple encryption with the shared secret
                RustyCrypto.tripleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
            } catch (e: Exception) {
                -1 // failure
            } finally {
                inputFd.close()
                outputFd.close()
            }
            
            if (success == 0) {
                File(outputPath).readBytes()
            } else {
                throw Exception("Encryption failed")
            }
        } catch (e: Exception) {
            throw Exception("Failed to encrypt text: ${e.message}")
        }
    }

    private fun decryptReceivedText(encryptedData: ByteArray): String {
        return try {
            // Write encrypted data to temp file
            val encryptedFile = File.createTempFile("received_encrypted", ".txt", cacheDir)
            encryptedFile.writeBytes(encryptedData)
            
            val decryptedPath = "${encryptedFile.absolutePath}.decrypted"
            // Open file descriptors for real decryption
            val inputFd = ParcelFileDescriptor.open(encryptedFile, ParcelFileDescriptor.MODE_READ_ONLY)
            val outputFd = ParcelFileDescriptor.open(File(decryptedPath), ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
            
            val success = try {
                // Use real triple decryption with the shared secret
                RustyCrypto.tripleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
            } catch (e: Exception) {
                -1 // failure
            } finally {
                inputFd.close()
                outputFd.close()
            }
            
            if (success == 0) {
                File(decryptedPath).readText()
            } else {
                throw Exception("Decryption failed")
            }
        } catch (e: Exception) {
            "Failed to decrypt text: ${e.message}"
        }
    }

    private fun createTempTextFile() {
        try {
            tempTextFile = File.createTempFile("secure_share_text", ".txt", cacheDir)
            FileWriter(tempTextFile!!).use { writer ->
                writer.write(inputText)
            }
        } catch (e: Exception) {
            showError("Failed to create temporary text file: ${e.message}")
        }
    }

    private fun showError(message: String) {
        binding.tvStatus.text = "Error: $message"
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun showSuccess(message: String) {
        binding.tvStatus.text = message
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(bluetoothReceiver)
        } catch (_: Exception) {}
        
        bluetoothSocket?.close()
        serverSocket?.close()
        tempTextFile?.delete()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSIONS_REQUEST_CODE) {
            if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                onPermissionsGranted()
            } else {
                showError("Bluetooth permissions required for secure share")
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_ENABLE_BT -> {
                if (resultCode == Activity.RESULT_OK) {
                    checkPermissions()
                } else {
                    showError("Bluetooth must be enabled for secure share")
                }
            }
            REQUEST_DISCOVERABLE_BT -> {
                if (resultCode > 0) {
                    binding.tvStatus.text = "Device is discoverable for $resultCode seconds"
                }
            }
        }
    }
}
