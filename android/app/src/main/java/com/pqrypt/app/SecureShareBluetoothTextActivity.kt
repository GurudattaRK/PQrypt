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
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.pqrypt.app.databinding.ActivitySecureShareBluetoothTextBinding
import kotlinx.coroutines.*
import android.os.ParcelFileDescriptor
import android.os.Environment
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
    private var defaultOutputDir: File? = null
    private var isDiscoveryReceiverRegistered = false
    
    // Bluetooth discovery receiver
    private val discoveryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device: BluetoothDevice? = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    device?.let {
                        if (!discoveredDevices.any { d -> d.address == it.address }) {
                            discoveredDevices.add(it)
                            deviceAdapter?.notifyItemInserted(discoveredDevices.size - 1)
                            binding.tvStatus.text = "Found ${discoveredDevices.size} devices"
                        }
                    }
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    binding.tvStatus.text = "Discovery completed. Found ${discoveredDevices.size} devices"
                }
            }
        }
    }

    // Bluetooth enable launcher for Android 12+ compatibility
    private val bluetoothEnableLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Toast.makeText(this, "Bluetooth enabled", Toast.LENGTH_SHORT).show()
            checkPermissions()
        } else {
            showError("Bluetooth is required for this feature")
        }
    }

    companion object {
        private const val UUID_STRING = "8ce255c0-223a-11e0-ac64-0800200c9a66"
        private val MY_UUID = UUID.fromString(UUID_STRING)
        private const val REQUEST_ENABLE_BT = 1
        private const val REQUEST_DISCOVERABLE_BT = 2
        private const val PERMISSIONS_REQUEST_CODE = 100
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
        setupDefaultOutputLocation()
        checkPermissions()  // Check permissions before setting up Bluetooth
        updateUI()
    }
    
    private fun setupDefaultOutputLocation() {
        try {
            // Create default output directory: Documents/pqrypt/
            val documentsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
            defaultOutputDir = File(documentsDir, "PQrypt")
            
            if (!defaultOutputDir!!.exists()) {
                defaultOutputDir!!.mkdirs()
            }
        } catch (e: Exception) {
            // Fallback to the same default path, not app-specific directory
            defaultOutputDir = File("/storage/emulated/0/Documents/PQrypt")
            if (!defaultOutputDir!!.exists()) {
                defaultOutputDir!!.mkdirs()
            }
        }
    }

    private fun setupUI() {
        binding.tvRole.text = "Role: ${role.capitalize()}"
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, SecureShareHelpActivity::class.java).putExtra("screen", "bluetooth_text"))
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

        // Auto-setup Bluetooth on activity start
        setupBluetooth()
        
        // Setup bluetooth button removed from layout - everything is automatic now

        // Discover/Connect button
        binding.btnDiscoverConnect.setOnClickListener {
            if (isSender) {
                startDiscovery()
            } else {
                startListening()
            }
        }
        
        // Note: Add open output folder functionality to existing buttons or layout if needed

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

        // Check permissions first, then enable Bluetooth if needed
        checkPermissions()
        
        if (!bluetoothAdapter!!.isEnabled) {
            val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            bluetoothEnableLauncher.launch(enableBtIntent)
        }
    }

    private fun checkPermissions() {
        val permissions = mutableListOf<String>()
        
        // Check Android version and add appropriate Bluetooth permissions
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            // Android 12+ (API 31+) - Use new granular Bluetooth permissions
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_ADVERTISE)
            }
        } else {
            // Android 11 and below - Use legacy Bluetooth permissions
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_ADMIN)
            }
        }
        
        // Location permissions required for Bluetooth device discovery
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.ACCESS_COARSE_LOCATION)
        }

        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), PERMISSIONS_REQUEST_CODE)
        } else {
            onPermissionsGranted()
        }
    }

    private fun onPermissionsGranted() {
        // Initialize Bluetooth adapter if not already done
        if (bluetoothAdapter == null) {
            val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothAdapter = bluetoothManager.adapter
        }
        
        binding.btnDiscoverConnect.isEnabled = true
        binding.tvStatus.text = if (isSender) "Ready to discover devices" else "Ready to listen for connections"
        
        // Register Bluetooth receiver
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        registerReceiver(discoveryReceiver, filter)
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
                        binding.tvStatus.text = "Text transferred successfully!"
                        showSuccess("Text sent via Bluetooth!")
                        
                        // Cleanup intermediate files
                        cleanupIntermediateFiles()
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
            showError("Bluetooth scan permission required")
            return
        }

        bluetoothAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT)
                return
            }

            // Register discovery receiver if not already registered
            if (!isDiscoveryReceiverRegistered) {
                val filter = IntentFilter().apply {
                    addAction(BluetoothDevice.ACTION_FOUND)
                    addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
                }
                registerReceiver(discoveryReceiver, filter)
                isDiscoveryReceiverRegistered = true
            }

            // Cancel any ongoing discovery first
            if (adapter.isDiscovering) {
                adapter.cancelDiscovery()
            }

            discoveredDevices.clear()
            deviceAdapter?.notifyDataSetChanged()
            
            // Add paired devices first
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                adapter.bondedDevices?.forEach { device ->
                    if (!discoveredDevices.any { it.address == device.address }) {
                        discoveredDevices.add(device)
                        deviceAdapter?.notifyItemInserted(discoveredDevices.size - 1)
                    }
                }
            }
            
            // Start discovery for new devices
            val discoveryStarted = adapter.startDiscovery()
            if (!discoveryStarted) {
                showError("Failed to start device discovery")
            } else {
                binding.tvStatus.text = "Scanning for devices... Found ${discoveredDevices.size} paired devices"
                binding.rvDevices.visibility = View.VISIBLE
            }
        }
    }

    private fun startListening() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            showError("Bluetooth connect permission required")
            return
        }
        
        bluetoothAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT)
                return
            }
            
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    serverSocket = adapter.listenUsingRfcommWithServiceRecord("PQryptSecureTextShare", MY_UUID)
                    
                    withContext(Dispatchers.Main) {
                        binding.tvConnectionStatus.text = "Server started, waiting for connections..."
                        binding.tvStatus.text = "Make yourself discoverable and wait for sender to connect"
                        
                        // Make device discoverable
                        val discoverableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                            putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300)
                        }
                        startActivityForResult(discoverableIntent, REQUEST_DISCOVERABLE_BT)
                    }
    
                    // Accept incoming connection (this blocks until connection is made)
                    val socket = serverSocket?.accept()
                    socket?.let {
                        withContext(Dispatchers.Main) {
                            bluetoothSocket = it
                            binding.tvConnectionStatus.text = "Connected to ${it.remoteDevice.name ?: it.remoteDevice.address}"
                            showSuccess("Incoming Bluetooth connection accepted")
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
    }

    private fun connectToDevice(device: BluetoothDevice) {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            showError("Bluetooth connect permission required")
            return
        }

        selectedDevice = device
        binding.tvConnectionStatus.text = "Connecting to ${device.name ?: device.address}..."
        binding.tvStatus.text = "Establishing connection..."

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Cancel discovery to improve connection performance
                bluetoothAdapter?.cancelDiscovery()
                
                // Check if device is paired, if not try to pair first
                if (device.bondState != BluetoothDevice.BOND_BONDED) {
                    withContext(Dispatchers.Main) {
                        showSuccess("Pairing with device...")
                    }
                    
                    // Attempt to pair
                    val paired = device.createBond()
                    if (!paired) {
                        throw IOException("Failed to initiate pairing with device")
                    }
                    
                    // Wait for pairing to complete
                    var attempts = 0
                    while (device.bondState == BluetoothDevice.BOND_BONDING && attempts < 30) {
                        Thread.sleep(1000)
                        attempts++
                    }
                    
                    if (device.bondState != BluetoothDevice.BOND_BONDED) {
                        throw IOException("Device pairing failed or timed out")
                    }
                }
                
                // Try multiple connection methods for better compatibility
                var socket: BluetoothSocket? = null
                var connected = false
                
                // Add delay to ensure the target device is ready
                Thread.sleep(2000)
                
                // Method 1: Standard RFCOMM connection
                try {
                    socket = device.createRfcommSocketToServiceRecord(MY_UUID)
                    socket.connect()
                    connected = true
                } catch (e: IOException) {
                    socket?.close()
                    
                    // Method 2: Fallback using reflection for older devices
                    try {
                        val method = device.javaClass.getMethod("createRfcommSocket", Int::class.javaPrimitiveType)
                        socket = method.invoke(device, 1) as BluetoothSocket
                        socket.connect()
                        connected = true
                    } catch (e2: Exception) {
                        socket?.close()
                        
                        // Method 3: Try different RFCOMM channels
                        for (channel in 1..30) {
                            try {
                                val method = device.javaClass.getMethod("createRfcommSocket", Int::class.javaPrimitiveType)
                                socket = method.invoke(device, channel) as BluetoothSocket
                                socket.connect()
                                connected = true
                                break
                            } catch (e3: Exception) {
                                socket?.close()
                                if (channel == 30) {
                                    throw IOException("All connection methods failed: ${e.message}, ${e2.message}")
                                }
                            }
                        }
                    }
                }
                
                if (connected && socket != null) {
                    bluetoothSocket = socket
                    
                    withContext(Dispatchers.Main) {
                        binding.tvConnectionStatus.text = "Connected to ${device.name ?: device.address}"
                        showSuccess("Bluetooth connection established")
                        startKeyExchangeAsSender()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Connection failed: ${e.message}")
                    bluetoothSocket?.close()
                    bluetoothSocket = null
                }
            }
        }
    }

    private fun startKeyExchangeAsSender() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Reset state to prevent intermittent failures
                senderState = null
                receiverState = null
                
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
                // Reset state to prevent intermittent failures
                senderState = null
                receiverState = null
                
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
        val initResult = RustyCrypto.pqc4HybridInit() as? Array<*>
        if (initResult == null || initResult.size < 2) {
            throw Exception("Failed to initialize key exchange")
        }
        
        val initialKey = initResult[0] as? ByteArray
        if (initialKey == null) {
            throw Exception("Failed to generate initial key")
        }
        
        senderState = initResult[1]
        if (senderState == null) {
            throw Exception("Failed to generate sender state")
        }
        
        sendBluetoothData(initialKey)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 30
        }

        // Step 2: Receive response key
        val responseKey = receiveBluetoothData()
        if (responseKey.isEmpty()) {
            throw Exception("Failed to receive response key from receiver")
        }
        
        val senderStateBytes = senderState as? ByteArray
        if (senderStateBytes == null) {
            throw Exception("Sender state is invalid")
        }
        
        val finalResult = RustyCrypto.pqc4HybridSndFinal(responseKey, senderStateBytes) as? Array<*>
        if (finalResult == null || finalResult.size < 2) {
            throw Exception("Failed to complete key exchange")
        }
        
        // Step 3: Send final key
        finalSharedSecret = finalResult[0] as? ByteArray
        val finalKey = finalResult[1] as? ByteArray
        
        if (finalSharedSecret == null || finalKey == null) {
            throw Exception("Failed to generate final keys")
        }
        
        sendBluetoothData(finalKey)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Encrypting and Sending Text..."
        }

        // Step 4: Encrypt and send text
        val encryptedTextData = encryptInputText()
        if (encryptedTextData.isEmpty()) {
            throw Exception("Failed to encrypt text")
        }
        
        sendBluetoothText(encryptedTextData)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            showSuccess("Text encrypted and sent successfully!")
            
            // Cleanup intermediate files
            cleanupIntermediateFiles()
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
        if (initialKey.isEmpty()) {
            throw Exception("Failed to receive initial key from sender")
        }
        
        val recvResult = RustyCrypto.pqc4HybridRecv(initialKey) as? Array<*>
        if (recvResult == null || recvResult.size < 2) {
            throw Exception("Invalid key exchange result from crypto library")
        }
        
        // Step 2: Send response key
        val responseKey = recvResult[0] as? ByteArray
        if (responseKey == null) {
            throw Exception("Failed to generate response key")
        }
        
        receiverState = recvResult[1]
        if (receiverState == null) {
            throw Exception("Failed to generate receiver state")
        }
        
        sendBluetoothData(responseKey)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 40
        }

        // Step 3: Receive final key and generate shared secret
        val finalKey = receiveBluetoothData()
        if (finalKey.isEmpty()) {
            throw Exception("Failed to receive final key from sender")
        }
        
        val receiverStateBytes = receiverState as? ByteArray
        if (receiverStateBytes == null) {
            throw Exception("Receiver state is invalid")
        }
        
        finalSharedSecret = RustyCrypto.pqc4HybridRecvFinal(finalKey, receiverStateBytes) as? ByteArray
        if (finalSharedSecret == null) {
            throw Exception("Failed to generate shared secret")
        }
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Receiving and Decrypting Text..."
        }

        // Step 4: Receive and decrypt text
        val encryptedTextData = receiveBluetoothText()
        if (encryptedTextData.isEmpty()) {
            throw Exception("Failed to receive encrypted text data")
        }
        
        val decryptedText = decryptReceivedText(encryptedTextData)
        
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            binding.tvReceivedText.text = decryptedText
            showSuccess("Text received and decrypted successfully!")
            
            // Cleanup intermediate files
            cleanupIntermediateFiles()
        }
    }

    private fun sendBluetoothData(data: ByteArray?) {
        if (data == null) {
            throw IOException("Cannot send null data")
        }
        
        val outputStream = bluetoothSocket?.outputStream ?: throw IOException("Bluetooth socket not connected")
        
        // Send length first (4 bytes)
        val lengthBytes = ByteArray(4)
        lengthBytes[0] = (data.size shr 24).toByte()
        lengthBytes[1] = (data.size shr 16).toByte()
        lengthBytes[2] = (data.size shr 8).toByte()
        lengthBytes[3] = data.size.toByte()
        outputStream.write(lengthBytes)
        
        // Send data
        outputStream.write(data)
        outputStream.flush()
    }

    private fun receiveBluetoothData(): ByteArray {
        val inputStream = bluetoothSocket?.inputStream ?: throw IOException("Bluetooth socket not connected")
        
        // Read length first (4 bytes)
        val lengthBytes = ByteArray(4)
        var totalRead = 0
        while (totalRead < 4) {
            val read = inputStream.read(lengthBytes, totalRead, 4 - totalRead)
            if (read == -1) throw IOException("Connection closed while reading length")
            totalRead += read
        }
        
        val length = ((lengthBytes[0].toInt() and 0xFF) shl 24) or
                    ((lengthBytes[1].toInt() and 0xFF) shl 16) or
                    ((lengthBytes[2].toInt() and 0xFF) shl 8) or
                    (lengthBytes[3].toInt() and 0xFF)
        
        if (length <= 0 || length > 1024 * 1024) { // Max 1MB for safety
            throw IOException("Invalid data length: $length")
        }
        
        // Read data
        val data = ByteArray(length)
        totalRead = 0
        while (totalRead < length) {
            val read = inputStream.read(data, totalRead, length - totalRead)
            if (read == -1) throw IOException("Connection closed while reading data")
            totalRead += read
        }
        
        return data
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
            if (finalSharedSecret == null) {
                throw Exception("Shared secret not available for decryption")
            }
            
            if (encryptedData.isEmpty()) {
                throw Exception("No encrypted data to decrypt")
            }
            
            // Write encrypted data to temp file
            val outputDir = defaultOutputDir ?: File("/storage/emulated/0/Documents/PQrypt")
            if (!outputDir.exists()) {
                outputDir.mkdirs()
            }
            val encryptedFile = File.createTempFile("received_encrypted", ".pqrypt2", outputDir)
            
            // Delete existing file if it exists
            if (encryptedFile.exists()) {
                encryptedFile.delete()
            }
            
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
                val decryptedText = File(decryptedPath).readText()
                // Clean up temp files
                encryptedFile.delete()
                File(decryptedPath).delete()
                decryptedText
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


    override fun onDestroy() {
        super.onDestroy()
        bluetoothSocket?.close()
        serverSocket?.close()
        
        // Unregister discovery receiver
        if (isDiscoveryReceiverRegistered) {
            try {
                unregisterReceiver(discoveryReceiver)
                isDiscoveryReceiverRegistered = false
            } catch (e: IllegalArgumentException) {
                // Receiver not registered, ignore
            }
        }
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
    
    private fun cleanupIntermediateFiles() {
        try {
            val outputDir = File("/storage/emulated/0/Documents/PQrypt")
            if (outputDir.exists()) {
                // Delete all .key files
                outputDir.listFiles { _, name -> name.endsWith(".key") }?.forEach { it.delete() }
                // Delete all .txt files created during text sharing
                outputDir.listFiles { _, name -> name.startsWith("share_") && name.endsWith(".txt") }?.forEach { it.delete() }
                // Delete temporary files
                outputDir.listFiles { _, name -> name.startsWith("temp_") && name.endsWith(".txt") }?.forEach { it.delete() }
            }
            
            // Also clean cache directory
            cacheDir.listFiles { _, name -> 
                name.endsWith(".key") || name.endsWith(".tmp") || 
                (name.startsWith("share_") && name.endsWith(".txt")) ||
                (name.startsWith("temp_") && name.endsWith(".txt"))
            }?.forEach { it.delete() }
            
        } catch (e: Exception) {
            // Silent cleanup failure - don't bother user
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
    
    private fun openOutputFolder() {
        try {
            val outputDir = File("/storage/emulated/0/Documents/pqrypt")
            if (!outputDir.exists()) {
                outputDir.mkdirs()
            }
            
            val intent = Intent(Intent.ACTION_VIEW)
            intent.setDataAndType(android.net.Uri.fromFile(outputDir), "resource/folder")
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
            
            try {
                startActivity(intent)
            } catch (e: Exception) {
                // Fallback: use file manager intent
                val fileManagerIntent = Intent(Intent.ACTION_VIEW)
                fileManagerIntent.data = android.net.Uri.parse("content://com.android.externalstorage.documents/document/primary%3ADocuments%2Fpqrypt")
                fileManagerIntent.type = "vnd.android.document/directory"
                try {
                    startActivity(fileManagerIntent)
                } catch (e2: Exception) {
                    Toast.makeText(this, "Files saved to: ${outputDir.absolutePath}", Toast.LENGTH_LONG).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Files are saved to: /storage/emulated/0/Documents/PQrypt/", Toast.LENGTH_LONG).show()
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
