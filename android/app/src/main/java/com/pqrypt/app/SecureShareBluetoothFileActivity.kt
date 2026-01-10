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
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.pqrypt.app.databinding.ActivitySecureShareBluetoothFileBinding
import kotlinx.coroutines.*
import android.os.ParcelFileDescriptor
import android.os.Environment
import java.io.*
import java.util.*
import android.location.LocationManager
import android.provider.Settings
import androidx.appcompat.app.AlertDialog
import android.util.Log

class SecureShareBluetoothFileActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareBluetoothFileBinding
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var deviceAdapter: BluetoothDeviceAdapter? = null
    private val discoveredDevices = mutableListOf<BluetoothDevice>()
    
    private var contentType = "file"
    private var transferMode = "bluetooth"
    private var role = "sender"
    private var isSender = true
    
    // File and connectivity state
    private var selectedFileUri: Uri? = null
    private var selectedFilePath = ""
    private var selectedDevice: BluetoothDevice? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var serverSocket: BluetoothServerSocket? = null
    
    // PQC Key exchange data
    private var senderState: Any? = null
    private var receiverState: Any? = null
    private var finalSharedSecret: ByteArray? = null
    private var defaultOutputDir: File? = null
    private var pickedFolderUri: Uri? = null
    private var pendingStartListening: Boolean = false
    
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

    private fun startBluetoothDiscoveryFallback() {
        bluetoothAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT)
                return
            }

            if (adapter.isDiscovering) {
                adapter.cancelDiscovery()
            }

            discoveredDevices.clear()
            deviceAdapter?.notifyDataSetChanged()

            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                adapter.bondedDevices?.forEach { device ->
                    if (!discoveredDevices.any { it.address == device.address }) {
                        discoveredDevices.add(device)
                        deviceAdapter?.notifyItemInserted(discoveredDevices.size - 1)
                    }
                }
            }

            val discoveryStarted = adapter.startDiscovery()
            if (!discoveryStarted) {
                showError("Failed to start device discovery")
            } else {
                binding.tvStatus.text = "Scanning for devices... Found ${discoveredDevices.size} paired devices"
                binding.rvDevices.visibility = View.VISIBLE
            }
        }
    }

    private suspend fun sendEncryptedFileStream() {
        val inputPath = getRealPathFromUri(selectedFileUri!!)
            ?: throw Exception("Cannot access file")
        val inFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
        val pipe = ParcelFileDescriptor.createPipe()
        val pipeRead = pipe[0]
        val pipeWrite = pipe[1]

        val encJob = kotlinx.coroutines.GlobalScope.async(Dispatchers.IO) {
            try {
                RustyCrypto.doubleEncryptFd(finalSharedSecret!!, false, inFd.fd, pipeWrite.fd)
            } finally {
                try { inFd.close() } catch (_: Exception) {}
                try { pipeWrite.close() } catch (_: Exception) {}
            }
        }

        val out = currentOutputStream()
        val src = ParcelFileDescriptor.AutoCloseInputStream(pipeRead)
        val buf = ByteArray(16 * 1024)
        var read: Int
        var sentBytes = 0L
        val startTs = System.currentTimeMillis()
        var lastLog = startTs
        var lastProgress = startTs
        val watchdog = kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(5000)
                if (System.currentTimeMillis() - lastProgress > 30000) {
                    Log.e(TAG, "Send stalled >30s; aborting transport")
                    try { bluetoothSocket?.close() } catch (_: Exception) {}
                    break
                }
            }
        }
        try {
            while (true) {
                read = src.read(buf)
                if (read <= 0) break
                val sizeBytes = byteArrayOf(
                    ((read ushr 24) and 0xFF).toByte(),
                    ((read ushr 16) and 0xFF).toByte(),
                    ((read ushr 8) and 0xFF).toByte(),
                    (read and 0xFF).toByte()
                )
                out.write(sizeBytes)
                out.write(buf, 0, read)
                sentBytes += read
                lastProgress = System.currentTimeMillis()
                val now = lastProgress
                if (now - lastLog >= 1000) {
                    val mb = sentBytes / (1024.0 * 1024.0)
                    val speed = mb / (((now - startTs).coerceAtLeast(1)) / 1000.0)
                    Log.d(TAG, "TX ${String.format("%.2f", mb)} MB @ ${String.format("%.2f", speed)} MB/s")
                    lastLog = now
                }
            }
            out.write(byteArrayOf(0, 0, 0, 0))
            out.flush()
            encJob.await()
        } finally {
            watchdog.cancel()
        }
    }

    private suspend fun receiveAndDecryptFileStream(originalFileName: String, treeUri: Uri): String {
        val partialName = "$originalFileName.partial"
        val outUri = createUniqueDocumentCopySuffix(treeUri, "application/octet-stream", partialName)
            ?: throw IOException("Failed to create output file in selected folder")
        val outFd = contentResolver.openFileDescriptor(outUri, "w")
            ?: throw IOException("Unable to open output descriptor")
        val pipe = ParcelFileDescriptor.createPipe()
        val pipeRead = pipe[0]
        val pipeWrite = pipe[1]

        val decJob = kotlinx.coroutines.GlobalScope.async(Dispatchers.IO) {
            try {
                RustyCrypto.doubleDecryptFd(finalSharedSecret!!, false, pipeRead.fd, outFd.fd)
            } finally {
                try { pipeRead.close() } catch (_: Exception) {}
                try { outFd.close() } catch (_: Exception) {}
            }
        }

        val sink = ParcelFileDescriptor.AutoCloseOutputStream(pipeWrite)
        val `in` = currentInputStream()
        val lenBuf = ByteArray(4)
        var recvBytes = 0L
        val startTs = System.currentTimeMillis()
        var lastLog = startTs
        var lastProgress = startTs
        val watchdog = kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(5000)
                if (System.currentTimeMillis() - lastProgress > 30000) {
                    Log.e(TAG, "Recv stalled >30s; aborting transport")
                    try { bluetoothSocket?.close() } catch (_: Exception) {}
                    break
                }
            }
        }
        while (true) {
            var total = 0
            while (total < 4) {
                val r = `in`.read(lenBuf, total, 4 - total)
                if (r == -1) throw IOException("Connection closed while reading chunk length")
                total += r
            }
            val size = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                       ((lenBuf[1].toInt() and 0xFF) shl 16) or
                       ((lenBuf[2].toInt() and 0xFF) shl 8) or
                       (lenBuf[3].toInt() and 0xFF)
            if (size == 0) break
            var remaining = size
            val buf = ByteArray(16 * 1024)
            while (remaining > 0) {
                val toRead = minOf(remaining, buf.size)
                val r = `in`.read(buf, 0, toRead)
                if (r == -1) throw IOException("Connection closed while reading chunk data")
                sink.write(buf, 0, r)
                remaining -= r
                recvBytes += r
                lastProgress = System.currentTimeMillis()
                val now = lastProgress
                if (now - lastLog >= 1000) {
                    val mb = recvBytes / (1024.0 * 1024.0)
                    val speed = mb / (((now - startTs).coerceAtLeast(1)) / 1000.0)
                    Log.d(TAG, "RX ${String.format("%.2f", mb)} MB @ ${String.format("%.2f", speed)} MB/s")
                    lastLog = now
                }
            }
        }
        sink.flush()
        sink.close()
        val result = try { decJob.await() } finally { watchdog.cancel() }
        return if (result == RustyCrypto.CRYPTO_SUCCESS) {
            try {
                val renamed = android.provider.DocumentsContract.renameDocument(contentResolver, outUri, originalFileName)
                (renamed ?: outUri).toString()
            } catch (_: Exception) {
                outUri.toString()
            }
        } else {
            try { android.provider.DocumentsContract.deleteDocument(contentResolver, outUri) } catch (_: Exception) {}
            throw IOException("Decryption failed (code=$result)")
        }
    }

    private fun currentInputStream(): InputStream {
        return bluetoothSocket?.inputStream ?: throw IOException("No active transport")
    }

    private fun currentOutputStream(): OutputStream {
        return bluetoothSocket?.outputStream ?: throw IOException("No active transport")
    }

    companion object {
        private const val UUID_STRING = "8ce255c0-223a-11e0-ac64-0800200c9a66"
        private val MY_UUID = UUID.fromString(UUID_STRING)
        private const val REQUEST_ENABLE_BT = 1
        private const val REQUEST_DISCOVERABLE_BT = 2
        private const val PERMISSIONS_REQUEST_CODE = 100
        private const val TAG = "PQrypt"
    }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                selectedFileUri = uri
                selectedFilePath = getFileName(uri) ?: "Unknown file"
                binding.tvSelectedFile.text = "Selected: $selectedFilePath"
                updateUI()
                
                // Auto-generate keys when file is selected
                if (isSender) {
                    autoGenerateInitialKeys()
                }
            }
        }
    }

    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val data = result.data
            val treeUri = data?.data
            if (treeUri != null) {
                val flags = data.flags
                try {
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        (flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION))
                    )
                } catch (_: Exception) {}
                pickedFolderUri = treeUri
                binding.tvStatus.text = "Destination folder selected"
                if (pendingStartListening) {
                    pendingStartListening = false
                    startListening()
                }
            }
        }
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
        binding = ActivitySecureShareBluetoothFileBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Get intent extras
        contentType = intent.getStringExtra("content_type") ?: "file"
        transferMode = intent.getStringExtra("transfer_mode") ?: "bluetooth"
        role = intent.getStringExtra("role") ?: "sender"
        isSender = role == "sender"

        setupUI()
        setupDefaultOutputLocation()
        checkPermissions()  // Check permissions before setting up Bluetooth
        ensureLocationEnabledOrPrompt()
        updateUI()
    }
    
    private fun setupDefaultOutputLocation() {
        try {
            val base = getExternalFilesDir(android.os.Environment.DIRECTORY_DOCUMENTS) ?: filesDir
            defaultOutputDir = java.io.File(base, "PQrypt")
            if (!defaultOutputDir!!.exists()) {
                defaultOutputDir!!.mkdirs()
            }
        } catch (e: Exception) {
            val base = filesDir
            defaultOutputDir = java.io.File(base, "PQrypt")
            if (!defaultOutputDir!!.exists()) {
                defaultOutputDir!!.mkdirs()
            }
        }
    }

    private fun setupUI() {
        binding.tvRole.text = "Role: ${role.capitalize()}"
        
        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, SecureShareHelpActivity::class.java).putExtra("screen", "bluetooth_file"))
        }

        // File selection (sender only)
        binding.btnChooseFile.setOnClickListener {
            openFilePicker()
        }

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
        binding.tvStatus.text = if (isSender) "Sender: After receiver taps 'Listen for Connection', tap 'Discover Devices' and connect." else "Receiver: Tap 'Listen for Connection' first and keep this screen open, then wait for sender."
        
        // Register Bluetooth receiver
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        registerReceiver(bluetoothReceiver, filter)
    }

    private fun updateUI() {
        // Show/hide UI elements based on role
        binding.llFileSelection.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.rvDevices.visibility = if (isSender) View.VISIBLE else View.GONE
        
        // Update button texts
        binding.btnDiscoverConnect.text = if (isSender) "Discover Devices" else "Listen for Connection"
        
        // Enable discover/connect based on readiness
        if (isSender) {
            binding.btnDiscoverConnect.isEnabled = selectedFileUri != null && bluetoothAdapter?.isEnabled == true
        }
    }

    private fun autoGenerateInitialKeys() {
        if (!isSender) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = RustyCrypto.hybridSenderInit()
                if (result != null && result.isNotEmpty()) {
                    // Store sender state for later use
                    // Implementation would store state from hybrid init
                    withContext(Dispatchers.Main) {
                        binding.tvStatus.text = "Keys generated. Ready to connect via Bluetooth."
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
        if (pickedFolderUri == null) {
            pendingStartListening = true
            binding.tvStatus.text = "Select destination folder, then listening will start"
            launchPickFolder()
            return
        }
        startBluetoothListenFallback()
    }

    private fun startBluetoothListenFallback() {
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
                    serverSocket = adapter.listenUsingRfcommWithServiceRecord("PQryptSecureShare", MY_UUID)
                    
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
                // Perform full key exchange and file transfer
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
                // Perform full key exchange and file reception
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
            binding.tvProgressTitle.text = "Encrypting and Sending File..."
        }
        val originalFileName = getFileName(selectedFileUri!!) ?: "unknown_file"
        // Send file name over Bluetooth (control channel)
        sendBluetoothFileName(originalFileName)
        sendEncryptedFileStream()
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            showSuccess("File encrypted and sent successfully!")
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
            binding.tvProgressTitle.text = "Receiving and Decrypting File..."
        }
        // Receive file name via Bluetooth (control channel)
        val originalFileName = receiveBluetoothFileName()
        val decryptedFilePath = receiveAndDecryptFileStream(originalFileName, pickedFolderUri!!)
        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            showOutputLocation("File received and decrypted to:", decryptedFilePath)
            cleanupIntermediateFiles()
        }
    }

    private fun launchPickFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
            try {
                val hinted = buildPQryptInitialTreeUri()
                if (hinted != null) {
                    putExtra("android.provider.extra.INITIAL_URI", hinted)
                }
            } catch (_: Exception) {}
        }
        folderPickerLauncher.launch(intent)
    }

    private fun buildPQryptInitialTreeUri(): Uri? {
        return try {
            val docs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
            val pqrypt = File(docs, "PQrypt")
            if (!pqrypt.exists()) pqrypt.mkdirs()
            val authority = "com.android.externalstorage.documents"
            val docId = "primary:Documents/PQrypt"
            android.provider.DocumentsContract.buildTreeDocumentUri(authority, docId)
        } catch (_: Exception) {
            null
        }
    }

    private fun createUniqueDocumentCopySuffix(treeUri: Uri, mime: String, desiredName: String): Uri? {
        val treeDoc = androidx.documentfile.provider.DocumentFile.fromTreeUri(this, treeUri) ?: return null
        val existing = treeDoc.findFile(desiredName)
        if (existing != null && existing.exists()) {
            existing.delete()
        }
        val parentDocId = android.provider.DocumentsContract.getTreeDocumentId(treeUri)
        val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
        return android.provider.DocumentsContract.createDocument(contentResolver, parentDocUri, mime, desiredName)
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
        
        if (length <= 0 || length > 10 * 1024 * 1024) { // Max 10MB for files
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

    private fun sendBluetoothFile(fileData: ByteArray) {
        // Send file size first
        val sizeBytes = ByteArray(4)
        sizeBytes[0] = (fileData.size shr 24).toByte()
        sizeBytes[1] = (fileData.size shr 16).toByte()
        sizeBytes[2] = (fileData.size shr 8).toByte()
        sizeBytes[3] = fileData.size.toByte()
        
        bluetoothSocket?.outputStream?.write(sizeBytes)
        bluetoothSocket?.outputStream?.write(fileData)
        bluetoothSocket?.outputStream?.flush()
    }

    private fun sendBluetoothFileName(fileName: String) {
        val fileNameBytes = fileName.toByteArray(Charsets.UTF_8)
        val lengthBytes = ByteArray(4)
        lengthBytes[0] = (fileNameBytes.size shr 24).toByte()
        lengthBytes[1] = (fileNameBytes.size shr 16).toByte()
        lengthBytes[2] = (fileNameBytes.size shr 8).toByte()
        lengthBytes[3] = fileNameBytes.size.toByte()
        
        bluetoothSocket?.outputStream?.write(lengthBytes)
        bluetoothSocket?.outputStream?.write(fileNameBytes)
        bluetoothSocket?.outputStream?.flush()
    }
    
    private fun receiveBluetoothFileName(): String {
        // Read filename length first
        val lengthBuffer = ByteArray(4)
        bluetoothSocket?.inputStream?.read(lengthBuffer)
        val nameLength = ((lengthBuffer[0].toInt() and 0xFF) shl 24) or
                        ((lengthBuffer[1].toInt() and 0xFF) shl 16) or
                        ((lengthBuffer[2].toInt() and 0xFF) shl 8) or
                        (lengthBuffer[3].toInt() and 0xFF)
        
        // Read filename data
        val nameData = ByteArray(nameLength)
        var totalRead = 0
        while (totalRead < nameLength) {
            val bytesRead = bluetoothSocket?.inputStream?.read(nameData, totalRead, nameLength - totalRead) ?: 0
            totalRead += bytesRead
        }
        
        return String(nameData, Charsets.UTF_8)
    }

    private fun receiveBluetoothFile(): ByteArray {
        // Read file size first
        val sizeBuffer = ByteArray(4)
        bluetoothSocket?.inputStream?.read(sizeBuffer)
        val fileSize = ((sizeBuffer[0].toInt() and 0xFF) shl 24) or
                      ((sizeBuffer[1].toInt() and 0xFF) shl 16) or
                      ((sizeBuffer[2].toInt() and 0xFF) shl 8) or
                      (sizeBuffer[3].toInt() and 0xFF)
        
        // Read file data
        val fileData = ByteArray(fileSize)
        var totalRead = 0
        while (totalRead < fileSize) {
            val bytesRead = bluetoothSocket?.inputStream?.read(fileData, totalRead, fileSize - totalRead) ?: 0
            totalRead += bytesRead
        }
        
        return fileData
    }

    private fun encryptSelectedFile(): ByteArray {
        return try {
            val inputPath = getRealPathFromUri(selectedFileUri!!)
                ?: throw Exception("Cannot access file")
            val outputPath = "${inputPath}.encrypted"
            
            // Open file descriptors for real encryption
            val inputFd = ParcelFileDescriptor.open(File(inputPath), ParcelFileDescriptor.MODE_READ_ONLY)
            val outputFd = ParcelFileDescriptor.open(File(outputPath), ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
            
            try {
                val result = RustyCrypto.doubleEncryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                if (result != 0) throw Exception("Encryption failed")
                File(outputPath).readBytes()
            } finally {
                inputFd.close()
                outputFd.close()
            }
        } catch (e: Exception) {
            throw Exception("Failed to encrypt file: ${e.message}")
        }
    }

    private fun decryptReceivedFile(encryptedData: ByteArray, originalFileName: String): String {
        return try {
            val outputDir = defaultOutputDir ?: (getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)?.let { File(it, "PQrypt") } ?: File(filesDir, "PQrypt"))
            if (!outputDir.exists()) {
                outputDir.mkdirs()
            }
            val tempEncFile = File.createTempFile("received_encrypted", ".pqrypt2", outputDir)
            
            // Delete existing file if it exists
            if (tempEncFile.exists()) {
                tempEncFile.delete()
            }
            
            tempEncFile.writeBytes(encryptedData)
            
            // Use original filename for the decrypted file
            val decryptedFile = File(outputDir, originalFileName)
            
            // Open file descriptors for real decryption
            val inputFd = ParcelFileDescriptor.open(tempEncFile, ParcelFileDescriptor.MODE_READ_ONLY)
            val outputFd = ParcelFileDescriptor.open(decryptedFile, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_WRITE_ONLY)
            
            try {
                val result = RustyCrypto.doubleDecryptFd(finalSharedSecret!!, false, inputFd.fd, outputFd.fd)
                if (result != 0) throw Exception("Decryption failed")
                // File decrypted successfully - return full path
                decryptedFile.absolutePath
            } finally {
                inputFd.close()
                outputFd.close()
                tempEncFile.delete()
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun openFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        filePickerLauncher.launch(intent)
    }


    private fun getRealPathFromUri(uri: Uri): String? {
        return try {
            // For content URIs, copy to cache directory
            if (uri.scheme == "content") {
                val tempFile = File.createTempFile("share_", ".tmp", cacheDir)
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                tempFile.absolutePath
            } else {
                uri.path
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun getFileName(uri: Uri): String? {
        return contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex("_display_name")
            if (nameIndex >= 0 && cursor.moveToFirst()) {
                cursor.getString(nameIndex)
            } else null
        }
    }


    private fun openOutputFolder() {
        try {
            val treeUri = pickedFolderUri
            if (treeUri != null) {
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(treeUri, "vnd.android.document/directory")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                }
                if (intent.resolveActivity(packageManager) != null) {
                    startActivity(intent)
                } else {
                    // Fallback: show the URI
                    Toast.makeText(this, "Folder: $treeUri", Toast.LENGTH_LONG).show()
                }
            } else {
                Toast.makeText(this, "Please select a destination folder first", Toast.LENGTH_LONG).show()
                launchPickFolder()
            }
        } catch (_: Exception) {
            Toast.makeText(this, "Unable to open folder", Toast.LENGTH_LONG).show()
        }
    }

    private fun showError(message: String) {
        binding.tvStatus.text = "Error: $message"
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun showSuccess(message: String) {
        binding.tvStatus.text = message
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        try { unregisterReceiver(bluetoothReceiver) } catch (_: Exception) {}
        try { bluetoothSocket?.close() } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
    }

    
    private fun showOutputLocation(message: String, path: String) {
        binding.tvStatus.text = "$message\n$path"
        Toast.makeText(this, "$message $path", Toast.LENGTH_LONG).show()
    }
    
    private fun cleanupIntermediateFiles() {
        try {
            val outputDir = defaultOutputDir ?: (getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)?.let { File(it, "PQrypt") } ?: File(filesDir, "PQrypt"))
            if (outputDir.exists()) {
                // Delete all .key files
                outputDir.listFiles { _, name -> name.endsWith(".key") }?.forEach { it.delete() }
                // Delete all .pqrypt2 files except the final ones we want to keep
                outputDir.listFiles { _, name -> name.contains("received_encrypted") && name.endsWith(".pqrypt2") }?.forEach { it.delete() }
                // Delete temporary files
                outputDir.listFiles { _, name -> name.startsWith("share_") && name.endsWith(".tmp") }?.forEach { it.delete() }
            }
            
            // Also clean cache directory
            cacheDir.listFiles { _, name -> 
                name.endsWith(".key") || name.endsWith(".tmp") || 
                (name.contains("received_encrypted") && name.endsWith(".pqrypt2"))
            }?.forEach { it.delete() }
            
        } catch (e: Exception) {
            // Failed to clean up intermediate files
        }
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
