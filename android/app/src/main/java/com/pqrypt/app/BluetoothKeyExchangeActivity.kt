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
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.pqrypt.app.databinding.ActivityBluetoothKeyExchangeBinding
import kotlinx.coroutines.*
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.*

class BluetoothKeyExchangeActivity : AppCompatActivity() {

    private lateinit var binding: ActivityBluetoothKeyExchangeBinding
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var deviceAdapter: BluetoothDeviceAdapter? = null
    private val discoveredDevices = mutableListOf<BluetoothDevice>()
    
    // Key exchange state
    private var isSender: Boolean = false
    private var selectedDevice: BluetoothDevice? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var serverSocket: BluetoothServerSocket? = null
    private var outputFolderUri: Uri? = null
    
    // PQC Key exchange data
    private var senderState: ByteArray? = null
    private var receiverState: ByteArray? = null
    private var hybrid1Key: ByteArray? = null
    private var hybrid2Key: ByteArray? = null
    private var hybrid3Key: ByteArray? = null
    private var finalSharedSecret: ByteArray? = null
    
    companion object {
        private const val UUID_STRING = "8ce255c0-223a-11e0-ac64-0800200c9a66"
        private val MY_UUID = UUID.fromString(UUID_STRING)
        private const val REQUEST_ENABLE_BT = 1
        private const val REQUEST_DISCOVERABLE_BT = 2
        private const val PERMISSIONS_REQUEST_CODE = 100
    }

    private val bluetoothEnableLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Toast.makeText(this, "Bluetooth enabled", Toast.LENGTH_SHORT).show()
            updateDeviceInfo()
            if (isSender) {
                makeDiscoverable()
            }
        } else {
            Toast.makeText(this, "Bluetooth is required for this feature", Toast.LENGTH_SHORT).show()
        }
    }

    private val discoverableLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != Activity.RESULT_CANCELED) {
            Toast.makeText(this, "Device is now discoverable", Toast.LENGTH_SHORT).show()
        }
    }

    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val treeUri = result.data?.data
            if (treeUri != null) {
                try {
                    val flags = result.data?.flags ?: 0
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                    )
                    outputFolderUri = treeUri
                    binding.tvOutputPath.text = "Output: ${treeUri.path}"
                    getSharedPreferences("pqrypt_prefs", MODE_PRIVATE)
                        .edit().putString("bluetooth_output_folder", treeUri.toString()).apply()
                } catch (e: Exception) {
                    Toast.makeText(this, "Error setting output folder: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private val deviceFoundReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device: BluetoothDevice? = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    device?.let {
                        if (ActivityCompat.checkSelfPermission(this@BluetoothKeyExchangeActivity, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                            // Only add devices that are not already in the list
                            if (!discoveredDevices.any { existingDevice -> existingDevice.address == it.address }) {
                                discoveredDevices.add(it)
                                deviceAdapter?.notifyItemInserted(discoveredDevices.size - 1)
                                Toast.makeText(this@BluetoothKeyExchangeActivity, "Found device: ${it.name ?: it.address}", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    binding.progressScanning.visibility = View.GONE
                    Toast.makeText(this@BluetoothKeyExchangeActivity, "Device scan completed. Found ${discoveredDevices.size} devices", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityBluetoothKeyExchangeBinding.inflate(layoutInflater)
        setContentView(binding.root)

        initializeBluetooth()
        setupUI()
        setupRecyclerView()
        requestPermissions()
        
        // Load saved output folder
        val savedFolder = getSharedPreferences("pqrypt_prefs", MODE_PRIVATE)
            .getString("bluetooth_output_folder", null)
        if (!savedFolder.isNullOrEmpty()) {
            outputFolderUri = Uri.parse(savedFolder)
            binding.tvOutputPath.text = "Output: ${outputFolderUri?.path}"
        }
    }

    private fun initializeBluetooth() {
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter
        
        if (bluetoothAdapter == null) {
            Toast.makeText(this, "Bluetooth not supported on this device", Toast.LENGTH_LONG).show()
            finish()
            return
        }
        
        updateDeviceInfo()
    }

    private fun setupUI() {
        binding.btnBack.setOnClickListener {
            finish()
        }

        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java).putExtra("screen", "bluetooth"))
        }

        binding.btnChooseOutputPath.setOnClickListener {
            chooseOutputFolder()
        }

        binding.btnSenderRole.setOnClickListener {
            selectRole(true)
        }

        binding.btnReceiverRole.setOnClickListener {
            selectRole(false)
        }

    }

    private fun setupRecyclerView() {
        deviceAdapter = BluetoothDeviceAdapter(discoveredDevices) { device ->
            connectToDevice(device)
        }
        binding.rvDevices.layoutManager = LinearLayoutManager(this)
        binding.rvDevices.adapter = deviceAdapter
    }

    private fun requestPermissions() {
        val permissions = mutableListOf<String>()
        
        // Check Android version and add appropriate Bluetooth permissions
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            // Android 12+ (API 31+) - Use new granular Bluetooth permissions
            permissions.addAll(listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ))
        } else {
            // Older versions - Use legacy Bluetooth permissions
            permissions.addAll(listOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            ))
        }
        
        // Location permissions required for Bluetooth device discovery
        permissions.addAll(listOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        ))

        // Check which permissions are not yet granted
        val permissionsToRequest = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        // Show system permission dialog if any permissions are missing
        if (permissionsToRequest.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this, 
                permissionsToRequest.toTypedArray(), 
                PERMISSIONS_REQUEST_CODE
            )
        } else {
            // All permissions already granted
            updateDeviceInfo()
        }
    }


    private fun updateDeviceInfo() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            binding.tvDeviceName.text = "Device Name: Permission required"
            binding.tvDeviceAddress.text = "MAC Address: Permission required"
            return
        }
        
        bluetoothAdapter?.let { adapter ->
            binding.tvDeviceName.text = "Device Name: ${adapter.name ?: "Unknown"}"
            binding.tvDeviceAddress.text = "MAC Address: ${adapter.address ?: "Unknown"}"
        }
    }

    private fun enableBluetoothAndMakeDiscoverable() {
        bluetoothAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                bluetoothEnableLauncher.launch(enableBtIntent)
            } else {
                makeDiscoverable()
            }
        }
    }

    private fun makeDiscoverable() {
        val discoverableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
            putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300)
        }
        discoverableLauncher.launch(discoverableIntent)
        
        // Start server immediately after making discoverable
        startBluetoothServer()
        
        // Update connection status to show sender is discoverable
        binding.tvConnectionStatus.text = "Device is discoverable for 5 minutes"
        Toast.makeText(this, "Device is now discoverable to other devices", Toast.LENGTH_LONG).show()
    }

    private fun chooseOutputFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or 
                     Intent.FLAG_GRANT_WRITE_URI_PERMISSION or 
                     Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or 
                     Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        }
        folderPickerLauncher.launch(intent)
    }

    private fun selectRole(sender: Boolean) {
        isSender = sender
        
        // Update role selection label
        binding.tvRoleLabel.text = if (sender) "Role: Sender (Discoverable)" else "Role: Receiver (Scanning)"
        
        // Update button colors
        binding.btnSenderRole.backgroundTintList = ContextCompat.getColorStateList(
            this, if (sender) R.color.selected_button else R.color.unselected_button
        )
        binding.btnReceiverRole.backgroundTintList = ContextCompat.getColorStateList(
            this, if (!sender) R.color.selected_button else R.color.unselected_button
        )
        
        // Disable both buttons after selection
        binding.btnSenderRole.isEnabled = false
        binding.btnReceiverRole.isEnabled = false
        
        if (sender) {
            // Sender: Enable Bluetooth and make discoverable
            enableBluetoothAndMakeDiscoverable()
        } else {
            // Receiver: Start scanning for devices
            scanForDevices()
        }
    }

    private fun scanForDevices() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Bluetooth scan permission required", Toast.LENGTH_SHORT).show()
            return
        }

        bluetoothAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                // Show Android Bluetooth enable dialog for receiver too
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                bluetoothEnableLauncher.launch(enableBtIntent)
                return
            }

            // Cancel any ongoing discovery first
            if (adapter.isDiscovering) {
                adapter.cancelDiscovery()
            }

            discoveredDevices.clear()
            deviceAdapter?.notifyDataSetChanged()

            // Show device list UI
            binding.tvDevicesLabel.visibility = View.VISIBLE
            binding.rvDevices.visibility = View.VISIBLE

            // Register receiver for device discovery
            val filter = IntentFilter().apply {
                addAction(BluetoothDevice.ACTION_FOUND)
                addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
            }
            
            // Unregister first to avoid duplicate registrations
            try {
                unregisterReceiver(deviceFoundReceiver)
            } catch (e: Exception) {
                // Receiver not registered yet
            }
            registerReceiver(deviceFoundReceiver, filter)

            binding.progressScanning.visibility = View.VISIBLE
            
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
                Toast.makeText(this, "Failed to start device discovery", Toast.LENGTH_SHORT).show()
                binding.progressScanning.visibility = View.GONE
            } else {
                Toast.makeText(this, "Scanning for devices...", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun connectToDevice(device: BluetoothDevice) {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Bluetooth connect permission required", Toast.LENGTH_SHORT).show()
            return
        }

        selectedDevice = device
        binding.tvConnectionStatus.text = "Connecting to ${device.name ?: device.address}..."
        binding.progressScanning.visibility = View.VISIBLE

        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Cancel discovery to improve connection performance
                bluetoothAdapter?.cancelDiscovery()
                
                // Check if device is paired, if not try to pair first
                if (device.bondState != BluetoothDevice.BOND_BONDED) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@BluetoothKeyExchangeActivity, "Pairing with device...", Toast.LENGTH_SHORT).show()
                    }
                    
                    // Attempt to pair
                    val paired = device.createBond()
                    if (!paired) {
                        throw IOException("Failed to initiate pairing with device")
                    }
                    
                    // Wait for pairing to complete (simplified approach)
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
                        binding.progressScanning.visibility = View.GONE
                        binding.tvConnectionStatus.text = "Connected to ${device.name ?: device.address}"
                        Toast.makeText(this@BluetoothKeyExchangeActivity, "Bluetooth connection established", Toast.LENGTH_SHORT).show()
                        
                        // Auto-start key exchange when connection is established
                        if (outputFolderUri != null) {
                            startKeyExchange()
                        } else {
                            Toast.makeText(this@BluetoothKeyExchangeActivity, "Please select output folder first", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.progressScanning.visibility = View.GONE
                    binding.tvConnectionStatus.text = "Connection failed: ${e.message}"
                    Toast.makeText(this@BluetoothKeyExchangeActivity, "Connection failed: ${e.message}", Toast.LENGTH_LONG).show()
                    bluetoothSocket?.close()
                    bluetoothSocket = null
                }
            }
        }
    }

    private fun startBluetoothServer() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                serverSocket = bluetoothAdapter?.listenUsingRfcommWithServiceRecord("PQryptKeyExchange", MY_UUID)
                
                withContext(Dispatchers.Main) {
                    binding.tvConnectionStatus.text = "Waiting for connection..."
                    binding.progressScanning.visibility = View.VISIBLE
                }

                // Accept incoming connection (this blocks until connection is made)
                val socket = serverSocket?.accept()
                socket?.let {
                    bluetoothSocket = it
                    withContext(Dispatchers.Main) {
                        binding.progressScanning.visibility = View.GONE
                        binding.tvConnectionStatus.text = "Connected to ${it.remoteDevice.name ?: it.remoteDevice.address}"
                        Toast.makeText(this@BluetoothKeyExchangeActivity, "Incoming Bluetooth connection accepted", Toast.LENGTH_SHORT).show()
                        
                        // Auto-start key exchange when connection is established
                        if (outputFolderUri != null) {
                            startKeyExchange()
                        } else {
                            Toast.makeText(this@BluetoothKeyExchangeActivity, "Please select output folder first", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            } catch (e: IOException) {
                withContext(Dispatchers.Main) {
                    binding.progressScanning.visibility = View.GONE
                    binding.tvConnectionStatus.text = "Server error: ${e.message}"
                    Toast.makeText(this@BluetoothKeyExchangeActivity, "Server error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }


    private fun startKeyExchange() {
        if (bluetoothSocket == null || outputFolderUri == null) {
            Toast.makeText(this, "Please connect to a device and select output folder", Toast.LENGTH_LONG).show()
            return
        }

        binding.tvConnectionStatus.text = "Starting key exchange..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (isSender) {
                    performSenderExchange()
                } else {
                    performReceiverExchange()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@BluetoothKeyExchangeActivity, "Key exchange failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private suspend fun performSenderExchange() {
        val socket = bluetoothSocket ?: return
        val outputStream = socket.outputStream
        val inputStream = socket.inputStream

        try {
            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 1: Generating initial keys..."
            }

            // Step 1: Generate 1.key (hybrid1Key)
            val result1 = RustyCrypto.pqc4HybridInit() as Array<*>
            hybrid1Key = result1[0] as ByteArray
            senderState = result1[1] as ByteArray

            // Send 1.key to receiver
            sendData(outputStream, hybrid1Key!!)

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 2: Waiting for receiver response..."
            }

            // Step 2: Receive 2.key from receiver
            hybrid2Key = receiveData(inputStream)

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 3: Generating final keys..."
            }

            // Step 3: Generate 3.key and final secret
            val result2 = RustyCrypto.pqc4HybridSndFinal(hybrid2Key!!, senderState!!) as Array<*>
            finalSharedSecret = result2[0] as ByteArray
            hybrid3Key = result2[1] as ByteArray

            // Send 3.key to receiver
            sendData(outputStream, hybrid3Key!!)

            // Save final.key
            saveFinalKey()

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Key exchange completed successfully!"
                Toast.makeText(this@BluetoothKeyExchangeActivity, "Final key saved successfully", Toast.LENGTH_LONG).show()
            }

        } catch (e: Exception) {
            throw e
        }
    }

    private suspend fun performReceiverExchange() {
        val socket = bluetoothSocket ?: return
        val outputStream = socket.outputStream
        val inputStream = socket.inputStream

        try {
            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 1: Waiting for sender's key..."
            }

            // Step 1: Receive 1.key from sender
            hybrid1Key = receiveData(inputStream)

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 2: Generating response..."
            }

            // Step 2: Generate 2.key response
            val result1 = RustyCrypto.pqc4HybridRecv(hybrid1Key!!) as Array<*>
            hybrid2Key = result1[0] as ByteArray
            receiverState = result1[1] as ByteArray

            // Send 2.key to sender
            sendData(outputStream, hybrid2Key!!)

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Step 3: Waiting for final key..."
            }

            // Step 3: Receive 3.key from sender
            hybrid3Key = receiveData(inputStream)

            // Generate final shared secret
            finalSharedSecret = RustyCrypto.pqc4HybridRecvFinal(hybrid3Key!!, receiverState!!)

            // Save final.key
            saveFinalKey()

            withContext(Dispatchers.Main) {
                binding.tvConnectionStatus.text = "Key exchange completed successfully!"
                Toast.makeText(this@BluetoothKeyExchangeActivity, "Final key saved successfully", Toast.LENGTH_LONG).show()
            }

        } catch (e: Exception) {
            throw e
        }
    }

    private fun sendData(outputStream: OutputStream, data: ByteArray) {
        // Send length first
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

    private fun receiveData(inputStream: InputStream): ByteArray {
        // Read length first
        val lengthBytes = ByteArray(4)
        var totalRead = 0
        while (totalRead < 4) {
            val read = inputStream.read(lengthBytes, totalRead, 4 - totalRead)
            if (read == -1) throw IOException("Connection closed")
            totalRead += read
        }
        
        val length = ((lengthBytes[0].toInt() and 0xFF) shl 24) or
                    ((lengthBytes[1].toInt() and 0xFF) shl 16) or
                    ((lengthBytes[2].toInt() and 0xFF) shl 8) or
                    (lengthBytes[3].toInt() and 0xFF)
        
        // Read data
        val data = ByteArray(length)
        totalRead = 0
        while (totalRead < length) {
            val read = inputStream.read(data, totalRead, length - totalRead)
            if (read == -1) throw IOException("Connection closed")
            totalRead += read
        }
        
        return data
    }

    private suspend fun saveFinalKey() {
        val folderUri = outputFolderUri ?: return
        val finalKey = finalSharedSecret ?: return

        try {
            val treeDoc = androidx.documentfile.provider.DocumentFile.fromTreeUri(this, folderUri)
            val fileName = "final.key"
            
            // Check if file already exists and delete it to prevent conflicts
            val existingFile = treeDoc?.findFile(fileName)
            if (existingFile != null && existingFile.exists()) {
                existingFile.delete() // Delete existing file to prevent conflicts
            }
            
            // Create new file with exact name
            val parentDocId = android.provider.DocumentsContract.getTreeDocumentId(folderUri)
            val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(folderUri, parentDocId)
            val fileUri = android.provider.DocumentsContract.createDocument(contentResolver, parentDocUri, "application/octet-stream", fileName)

            fileUri?.let { uri ->
                contentResolver.openOutputStream(uri)?.use { outputStream ->
                    outputStream.write(finalKey)
                }
            }
        } catch (e: Exception) {
            throw IOException("Failed to save final key: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(deviceFoundReceiver)
        } catch (e: Exception) {
            // Receiver might not be registered
        }
        
        bluetoothSocket?.close()
        serverSocket?.close()
        bluetoothAdapter?.cancelDiscovery()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        if (requestCode == PERMISSIONS_REQUEST_CODE) {
            // Check if all requested permissions were granted
            val allGranted = grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            
            if (allGranted) {
                // All permissions granted - proceed with Bluetooth functionality
                Toast.makeText(this, "Bluetooth permissions granted", Toast.LENGTH_SHORT).show()
                updateDeviceInfo()
            } else {
                // Some permissions were denied
                val deniedPermissions = mutableListOf<String>()
                for (i in permissions.indices) {
                    if (grantResults[i] != PackageManager.PERMISSION_GRANTED) {
                        deniedPermissions.add(permissions[i])
                    }
                }
                
                // Show specific message about denied permissions
                val message = if (deniedPermissions.size == 1) {
                    "Permission denied: ${getPermissionName(deniedPermissions[0])}"
                } else {
                    "Multiple Bluetooth permissions were denied. This feature requires all permissions to work properly."
                }
                
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                
                // Close activity since Bluetooth functionality won't work without permissions
                finish()
            }
        }
    }
    
    private fun getPermissionName(permission: String): String {
        return when (permission) {
            Manifest.permission.BLUETOOTH_CONNECT -> "Bluetooth Connect"
            Manifest.permission.BLUETOOTH_SCAN -> "Bluetooth Scan"
            Manifest.permission.BLUETOOTH_ADVERTISE -> "Bluetooth Advertise"
            Manifest.permission.BLUETOOTH -> "Bluetooth"
            Manifest.permission.BLUETOOTH_ADMIN -> "Bluetooth Admin"
            Manifest.permission.ACCESS_FINE_LOCATION -> "Fine Location"
            Manifest.permission.ACCESS_COARSE_LOCATION -> "Coarse Location"
            else -> permission.substringAfterLast(".")
        }
    }

}
