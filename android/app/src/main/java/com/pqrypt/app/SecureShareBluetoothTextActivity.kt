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
import android.location.LocationManager
import android.provider.Settings
import androidx.appcompat.app.AlertDialog
import android.os.Looper
import android.util.Log
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.WpsInfo

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
    private var wifiP2pManager: WifiP2pManager? = null
    private var wifiChannel: WifiP2pManager.Channel? = null
    private var isWifiDirectActive: Boolean = false
    private var tcpServerSocket: java.net.ServerSocket? = null
    private var networkSocket: java.net.Socket? = null
    
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
            ensureLocationEnabledOrPrompt()
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
        private const val WIFI_PORT = 8988
        private const val TAG = "PQrypt"
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
                    // autoGenerateInitialKeys disabled
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
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
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
    
        binding.tvStatus.text = if (isSender) "Sender: After receiver taps 'Listen for Connection', tap 'Discover Devices' and connect." else "Receiver: Tap 'Listen for Connection' first and keep this screen open, then wait for sender."
}

    private fun autoGenerateInitialKeys() {
        return
    }

    private fun startDiscovery() {

        if (!ensureLocationEnabledOrPrompt()) return
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
                    while (device.bondState == BluetoothDevice.BOND_BONDING && attempts < 120) {
                        delay(1000)
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

        val package1 = RustyCrypto.hybridSenderInit()
        sendBluetoothData(package1)

        withContext(Dispatchers.Main) { binding.progressBar.progress = 30 }

        val package2Bundle = receiveBluetoothData()
        val third = RustyCrypto.hybridSenderThird(package2Bundle) as Array<*>
        val package3 = third[0] as ByteArray
        finalSharedSecret = third[1] as ByteArray
        sendBluetoothData(package3)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Encrypting and Sending Text..."
        }

        val encryptedTextData = encryptInputText()
        if (encryptedTextData.isEmpty()) throw Exception("Failed to encrypt text")

        // Propose Wi‑Fi Direct for data path
        sendBluetoothData("USE_WIFI".toByteArray(Charsets.UTF_8))
        val wifiResp = String(receiveBluetoothData(), Charsets.UTF_8)
        var wifiOk = false
        if (wifiResp == "WIFI_READY") {
            wifiOk = tryStartWifiDirectSender()
            if (!wifiOk) {
                sendBluetoothData("USE_BT".toByteArray(Charsets.UTF_8))
            }
        }
        if (wifiOk) {
            showSuccess("Wi‑Fi Direct connected for text transfer")
        } else {
            showError("Using Bluetooth for text transfer")
        }
        sendTextOverCurrentStream(encryptedTextData)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            showSuccess("Text encrypted and sent successfully!")
            cleanupIntermediateFiles()
        }
    }

    private suspend fun performReceiverFlow() {
        withContext(Dispatchers.Main) {
            binding.llProgress.visibility = View.VISIBLE
            binding.tvProgressTitle.text = "Performing Key Exchange..."
            binding.progressBar.progress = 10
        }

        val package1 = receiveBluetoothData()
        val package2Bundle = RustyCrypto.hybridReceiverDual(package1)
        sendBluetoothData(package2Bundle)

        withContext(Dispatchers.Main) { binding.progressBar.progress = 40 }

        val package3 = receiveBluetoothData()
        finalSharedSecret = RustyCrypto.hybridReceiverFinalDual(package3)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Receiving and Decrypting Text..."
        }

        // Check if sender requested Wi‑Fi Direct
        val req = String(receiveBluetoothData(), Charsets.UTF_8)
        var wifiOk = false
        if (req == "USE_WIFI") {
            wifiOk = tryStartWifiDirectReceiver()
            if (wifiOk) {
                sendBluetoothData("WIFI_READY".toByteArray(Charsets.UTF_8))
                waitForNetworkSocket(30000)
            } else {
                sendBluetoothData("WIFI_FAIL".toByteArray(Charsets.UTF_8))
            }
        }

        val encryptedTextData = receiveTextOverCurrentStream()
        if (encryptedTextData.isEmpty()) throw Exception("Failed to receive encrypted text data")
        val decryptedText = decryptReceivedText(encryptedTextData)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            binding.tvReceivedText.text = decryptedText
            showSuccess("Text received and decrypted successfully!")
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

    private fun sendTextOverCurrentStream(textData: ByteArray) {
        val out = currentOutputStream()
        val sizeBytes = ByteArray(4)
        sizeBytes[0] = (textData.size shr 24).toByte()
        sizeBytes[1] = (textData.size shr 16).toByte()
        sizeBytes[2] = (textData.size shr 8).toByte()
        sizeBytes[3] = textData.size.toByte()
        out.write(sizeBytes)
        out.write(textData)
        out.flush()
        Log.d(TAG, "TX ${textData.size} bytes (text)")
    }

    private fun receiveTextOverCurrentStream(): ByteArray {
        val input = currentInputStream()
        val sizeBuffer = ByteArray(4)
        var read = 0
        while (read < 4) {
            val r = input.read(sizeBuffer, read, 4 - read)
            if (r == -1) throw IOException("Connection closed while reading text size")
            read += r
        }
        val textSize = ((sizeBuffer[0].toInt() and 0xFF) shl 24) or
                      ((sizeBuffer[1].toInt() and 0xFF) shl 16) or
                      ((sizeBuffer[2].toInt() and 0xFF) shl 8) or
                      (sizeBuffer[3].toInt() and 0xFF)
        val textData = ByteArray(textSize)
        var totalRead = 0
        while (totalRead < textSize) {
            val r = input.read(textData, totalRead, textSize - totalRead)
            if (r == -1) throw IOException("Connection closed while reading text data")
            totalRead += r
        }
        Log.d(TAG, "RX ${textData.size} bytes (text)")
        return textData
    }

    private fun currentInputStream(): InputStream {
        networkSocket?.let { return it.getInputStream() }
        return bluetoothSocket?.inputStream ?: throw IOException("No active transport")
    }

    private fun currentOutputStream(): OutputStream {
        networkSocket?.let { return it.getOutputStream() }
        return bluetoothSocket?.outputStream ?: throw IOException("No active transport")
    }

    private suspend fun tryStartWifiDirectReceiver(): Boolean {
        return try {
            wifiP2pManager = getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
            wifiChannel = wifiP2pManager?.initialize(this, Looper.getMainLooper(), null)
            if (android.os.Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                false
            } else {
                val created = CompletableDeferred<Boolean>()
                withContext(Dispatchers.Main) {
                    wifiP2pManager?.createGroup(wifiChannel, object : WifiP2pManager.ActionListener {
                        override fun onSuccess() { created.complete(true) }
                        override fun onFailure(reason: Int) { created.complete(false) }
                    })
                }
                val ok = withTimeoutOrNull(15000) { created.await() } ?: false
                if (!ok) return false
                tcpServerSocket = java.net.ServerSocket(WIFI_PORT)
                val sock = withTimeoutOrNull(30000) { tcpServerSocket!!.accept() } ?: return false
                networkSocket = sock
                isWifiDirectActive = true
                true
            }
        } catch (_: Exception) { false }
    }

    private suspend fun tryStartWifiDirectSender(): Boolean {
        return try {
            wifiP2pManager = getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
            wifiChannel = wifiP2pManager?.initialize(this, Looper.getMainLooper(), null)
            if (android.os.Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                false
            } else {
                val disc = CompletableDeferred<Boolean>()
                withContext(Dispatchers.Main) {
                    wifiP2pManager?.discoverPeers(wifiChannel, object : WifiP2pManager.ActionListener {
                        override fun onSuccess() { disc.complete(true) }
                        override fun onFailure(reason: Int) { disc.complete(false) }
                    })
                }
                val started = withTimeoutOrNull(10000) { disc.await() } ?: false
                if (!started) return false
                delay(2000)
                val peersDef = CompletableDeferred<Collection<WifiP2pDevice>>()
                withContext(Dispatchers.Main) {
                    wifiP2pManager?.requestPeers(wifiChannel) { list -> peersDef.complete(list.deviceList) }
                }
                val peers = withTimeoutOrNull(10000) { peersDef.await() } ?: emptyList()
                if (peers.isEmpty()) return false
                val device = peers.first()
                val cfg = WifiP2pConfig().apply { deviceAddress = device.deviceAddress; wps.setup = WpsInfo.PBC }
                val conn = CompletableDeferred<Boolean>()
                withContext(Dispatchers.Main) { wifiP2pManager?.connect(wifiChannel, cfg, object : WifiP2pManager.ActionListener { override fun onSuccess() { conn.complete(true) } override fun onFailure(reason: Int) { conn.complete(false) } }) }
                val connected = withTimeoutOrNull(20000) { conn.await() } ?: false
                if (!connected) return false
                var info: WifiP2pInfo? = null
                val start = System.currentTimeMillis()
                while (System.currentTimeMillis() - start < 30000) {
                    val infoDef = CompletableDeferred<WifiP2pInfo>()
                    withContext(Dispatchers.Main) { wifiP2pManager?.requestConnectionInfo(wifiChannel) { i -> infoDef.complete(i) } }
                    info = withTimeoutOrNull(3000) { infoDef.await() }
                    if (info != null && info!!.groupFormed) break
                    delay(1000)
                }
                if (info == null || !info!!.groupFormed) return false
                if (info!!.isGroupOwner) {
                    tcpServerSocket = java.net.ServerSocket(WIFI_PORT)
                    val sock = withTimeoutOrNull(30000) { tcpServerSocket!!.accept() } ?: return false
                    networkSocket = sock
                } else {
                    val host = info!!.groupOwnerAddress.hostAddress
                    val sock = java.net.Socket()
                    sock.connect(java.net.InetSocketAddress(host, WIFI_PORT), 30000)
                    networkSocket = sock
                }
                isWifiDirectActive = true
                true
            }
        } catch (_: Exception) { false }
    }

    private suspend fun waitForNetworkSocket(timeoutMs: Long): Boolean {
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (networkSocket != null) return true
            delay(200)
        }
        return networkSocket != null
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
                RustyCrypto.doubleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
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
            val outputDir = cacheDir
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
                RustyCrypto.doubleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
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
        try { tcpServerSocket?.close() } catch (_: Exception) {}
        try { networkSocket?.close() } catch (_: Exception) {}
        try { wifiP2pManager?.removeGroup(wifiChannel, null) } catch (_: Exception) {}
        
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
            cacheDir.listFiles { _, name ->
                name.endsWith(".key") || name.endsWith(".tmp") ||
                (name.startsWith("share_") && name.endsWith(".txt")) ||
                (name.startsWith("temp_") && name.endsWith(".txt"))
            }?.forEach { it.delete() }
        } catch (e: Exception) {
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
        Toast.makeText(this, "Text is displayed on screen; no files saved.", Toast.LENGTH_LONG).show()
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

private fun isLocationEnabled(): Boolean {
    val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
    return lm.isProviderEnabled(LocationManager.GPS_PROVIDER) || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
}

private fun ensureLocationEnabledOrPrompt(): Boolean {
    if (isLocationEnabled()) return true
    AlertDialog.Builder(this)
        .setTitle("Location required")
        .setMessage("Enable Location to improve Bluetooth discovery and pairing.")
        .setPositiveButton("Open Settings") { _, _ ->
            startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
        }
        .setNegativeButton("Cancel", null)
        .show()
    return false
}
}
