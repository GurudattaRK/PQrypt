package com.pqrypt.app

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.NetworkInfo
import android.net.Uri
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.WpsInfo
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.pqrypt.app.databinding.ActivitySecureShareWifiDirectFileBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

class SecureShareWifiDirectFileActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecureShareWifiDirectFileBinding

    private var contentType = "file"
    private var transferMode = "wifi_direct"
    private var role = "sender"
    private var isSender = true

    private var selectedFileUri: Uri? = null
    private var selectedFilePath = ""
    private var pickedFolderUri: Uri? = null
    private var pendingStartListening = false

    private var wifiP2pManager: WifiP2pManager? = null
    private var wifiChannel: WifiP2pManager.Channel? = null

    private val peers = mutableListOf<WifiP2pDevice>()
    private var deviceAdapter: WifiDirectDeviceAdapter? = null
    private var selectedPeer: WifiP2pDevice? = null

    private var p2pReceiver: BroadcastReceiver? = null
    private var p2pFilter: IntentFilter? = null

    private var serverSocket: ServerSocket? = null
    private var dataSocket: Socket? = null
    private var acceptJob: Job? = null

    private var finalSharedSecret: ByteArray? = null

    private var wifiLock: WifiManager.WifiLock? = null
    private var wakeLock: PowerManager.WakeLock? = null

    private var permsOk = false

    private var preflightRunning = false

    private var groupCreated = false

    private data class InputRef(
        val path: String,
        val temp: File?
    )

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                selectedFileUri = uri
                selectedFilePath = getFileName(uri) ?: "Unknown file"
                binding.tvSelectedFile.text = "Selected: $selectedFilePath"
                runPreflight()
                updateUI()
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecureShareWifiDirectFileBinding.inflate(layoutInflater)
        setContentView(binding.root)

        contentType = intent.getStringExtra("content_type") ?: "file"
        transferMode = intent.getStringExtra("transfer_mode") ?: "wifi_direct"
        role = intent.getStringExtra("role") ?: "sender"
        isSender = role == "sender"

        setupUI()
        binding.tvStatus.text = "Checking requirements..."
        runPreflight()
    }

    override fun onResume() {
        super.onResume()
        runPreflight()
        acquireLocks()
    }

    override fun onPause() {
        super.onPause()
        try {
            if (p2pReceiver != null) unregisterReceiver(p2pReceiver)
        } catch (_: Exception) {}
        releaseLocks()
    }

    override fun onDestroy() {
        super.onDestroy()
        acceptJob?.cancel()
        try { dataSocket?.close() } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
        cleanupP2pGroup()
    }

    private fun setupUI() {
        binding.tvRole.text = role.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }

        binding.btnBack.setOnClickListener { finish() }
        binding.btnHelp.setOnClickListener {
            startActivity(Intent(this, SecureShareHelpActivity::class.java).putExtra("screen", "wifi_direct_file"))
        }

        binding.btnChooseFile.setOnClickListener { openFilePicker() }

        binding.btnDiscoverConnect.setOnClickListener {
            if (isSender) {
                startDiscovery()
            } else {
                startListening()
            }
        }

        if (isSender) {
            deviceAdapter = WifiDirectDeviceAdapter(peers) { dev ->
                selectedPeer = dev
                connectToPeer(dev)
            }
            binding.rvDevices.layoutManager = LinearLayoutManager(this)
            binding.rvDevices.adapter = deviceAdapter
        }

        binding.llFileSelection.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.rvDevices.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.btnDiscoverConnect.text = if (isSender) "Discover Devices" else "Listen for Connection"
    }

    private fun updateUI() {
        binding.llFileSelection.visibility = if (isSender) View.VISIBLE else View.GONE
        binding.rvDevices.visibility = if (isSender) View.VISIBLE else View.GONE

        val wifiOk = isWifiEnabled()
        val locOk = isLocationEnabled()
        val ready = permsOk && wifiOk && locOk

        binding.btnDiscoverConnect.isEnabled = if (!ready) {
            false
        } else if (isSender) {
            selectedFileUri != null
        } else {
            true
        }
    }

    private fun runPreflight() {
        if (preflightRunning) return
        preflightRunning = true
        try {
            val perms = mutableListOf<String>()
            if (Build.VERSION.SDK_INT >= 33) {
                perms.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION)

            val missingPerms = perms.filter {
                ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
            }

            if (missingPerms.isNotEmpty()) {
                permsOk = false
                binding.tvStatus.text = "Grant permissions to continue"
                Log.d(TAG, "Preflight: requesting permissions=$missingPerms")
                updateUI()
                ActivityCompat.requestPermissions(this, missingPerms.toTypedArray(), PERMISSIONS_REQUEST_CODE)
                return
            }

            permsOk = true

            if (!isWifiEnabled()) {
                binding.tvStatus.text = "Wi‑Fi is off. Turn it on to use Wi‑Fi Direct."
                Log.d(TAG, "Preflight: wifi disabled")
                updateUI()
                ensureWifiEnabledOrPrompt()
                return
            }

            if (!isLocationEnabled()) {
                binding.tvStatus.text = "Location is off. Enable it for Wi‑Fi Direct discovery."
                Log.d(TAG, "Preflight: location disabled")
                updateUI()
                ensureLocationEnabledOrPrompt()
                return
            }

            initP2p()
            ensureBatteryOptimizationsIgnoredOrPrompt()

            binding.tvStatus.text = if (!isSender) {
                "Receiver: Tap 'Listen for Connection' and keep this screen open."
            } else {
                if (selectedFileUri == null) "Sender: Choose a file to enable discovery." else "Sender: Tap 'Discover Devices' and connect."
            }

            Log.d(TAG, "Preflight: ready")
            updateUI()
        } finally {
            preflightRunning = false
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != PERMISSIONS_REQUEST_CODE) return

        val ok = grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        if (!ok) {
            showError("Wi‑Fi Direct permissions are required")
            openAppSettings()
            return
        }

        runPreflight()
    }

    private fun initP2p() {
        if (wifiP2pManager != null && wifiChannel != null && p2pReceiver != null && p2pFilter != null) {
            try {
                registerReceiver(p2pReceiver, p2pFilter)
            } catch (_: Exception) {}
            return
        }
        wifiP2pManager = getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
        wifiChannel = wifiP2pManager?.initialize(this, mainLooper, null)

        p2pFilter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }

        p2pReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1)
                        val enabled = state == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                        Log.d(TAG, "P2P state: $state")
                        if (!enabled) {
                            binding.tvConnectionStatus.text = "Wi‑Fi Direct is off"
                            binding.tvStatus.text = "Enable Wi‑Fi to use Wi‑Fi Direct"
                            ensureWifiEnabledOrPrompt()
                        }
                    }

                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                        requestPeers()
                    }

                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        @Suppress("DEPRECATION")
                        val netInfo = intent.getParcelableExtra<NetworkInfo>(WifiP2pManager.EXTRA_NETWORK_INFO)
                        Log.d(TAG, "P2P connection changed. connected=${netInfo?.isConnected}")
                        if (netInfo?.isConnected == true) {
                            requestConnectionInfo()
                        } else {
                            binding.tvConnectionStatus.text = "Disconnected"
                            lifecycleScope.launch(Dispatchers.IO) {
                                try { dataSocket?.close() } catch (_: Exception) {}
                                dataSocket = null
                            }
                        }
                    }

                    WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                        @Suppress("DEPRECATION")
                        val dev = intent.getParcelableExtra<WifiP2pDevice>(WifiP2pManager.EXTRA_WIFI_P2P_DEVICE)
                        Log.d(TAG, "This device: ${dev?.deviceName} status=${dev?.status}")
                    }
                }
            }
        }

        try {
            registerReceiver(p2pReceiver, p2pFilter)
        } catch (_: Exception) {}

        acquireLocks()
    }

    private fun requestPeers() {
        val mgr = wifiP2pManager ?: return
        val ch = wifiChannel ?: return

        mgr.requestPeers(ch) { list ->
            peers.clear()
            peers.addAll(list.deviceList)
            deviceAdapter?.notifyDataSetChanged()
            if (isSender) {
                binding.rvDevices.visibility = if (peers.isEmpty()) View.GONE else View.VISIBLE
                binding.tvStatus.text = if (peers.isEmpty()) "No devices found yet" else "Select a device to connect"
            }
        }
    }

    private fun requestConnectionInfo() {
        val mgr = wifiP2pManager ?: return
        val ch = wifiChannel ?: return

        mgr.requestConnectionInfo(ch) { info ->
            Log.d(TAG, "ConnInfo formed=${info.groupFormed} isGO=${info.isGroupOwner} go=${info.groupOwnerAddress?.hostAddress}")
            if (!info.groupFormed) return@requestConnectionInfo

            binding.tvConnectionStatus.text = if (info.isGroupOwner) "Connected (Group Owner)" else "Connected"

            if (isSender) {
                lifecycleScope.launch(Dispatchers.IO) {
                    ensureClientSocket(info)
                }
            }
        }
    }

    private fun startDiscovery() {
        startDiscovery(1)
    }

    private fun startDiscovery(attempt: Int) {
        if (!ensureWifiEnabledOrPrompt()) return
        if (!ensureLocationEnabledOrPrompt()) return

        val mgr = wifiP2pManager ?: run {
            initP2p()
            wifiP2pManager
        } ?: return
        val ch = wifiChannel ?: return

        binding.tvStatus.text = "Discovering Wi‑Fi Direct peers..."
        peers.clear()
        deviceAdapter?.notifyDataSetChanged()

        mgr.discoverPeers(ch, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                binding.tvStatus.text = "Discovery started. Waiting for peers..."
                lifecycleScope.launch(Dispatchers.Main) {
                    delay(1500)
                    requestPeers()
                }
            }

            override fun onFailure(reason: Int) {
                if (attempt >= 6) {
                    binding.tvStatus.text = "Discovery failed (reason=$reason)."
                    showError("Wi‑Fi Direct discovery failed. Try toggling Wi‑Fi and Location.")
                    return
                }
                binding.tvStatus.text = "Discovery failed (reason=$reason). Retrying ($attempt/6)..."
                lifecycleScope.launch(Dispatchers.Main) {
                    delay(1200L * attempt)
                    startDiscovery(attempt + 1)
                }
            }
        })
    }

    private fun startListening() {
        if (pickedFolderUri == null) {
            pendingStartListening = true
            binding.tvStatus.text = "Select destination folder, then listening will start"
            launchPickFolder()
            return
        }

        if (!ensureWifiEnabledOrPrompt()) return
        if (!ensureLocationEnabledOrPrompt()) return

        initP2p()
        binding.tvConnectionStatus.text = "Preparing group..."
        binding.tvStatus.text = "Creating Wi‑Fi Direct group (receiver is Group Owner)..."

        lifecycleScope.launch(Dispatchers.IO) {
            val ok = ensureGroupOwner()
            withContext(Dispatchers.Main) {
                if (!ok) {
                    showError("Failed to create Wi‑Fi Direct group")
                } else {
                    binding.tvConnectionStatus.text = "Group created. Waiting for sender..."
                    binding.tvStatus.text = "Keep this screen open until sender connects"
                }
            }
            if (ok) startTcpServerAccept()
        }
    }

    private suspend fun ensureGroupOwner(): Boolean {
        val mgr = wifiP2pManager ?: return false
        val ch = wifiChannel ?: return false

        cleanupP2pGroup()
        groupCreated = false

        val created = kotlinx.coroutines.CompletableDeferred<Boolean>()
        withContext(Dispatchers.Main) {
            mgr.createGroup(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    created.complete(true)
                }

                override fun onFailure(reason: Int) {
                    Log.e(TAG, "createGroup failed reason=$reason")
                    created.complete(false)
                }
            })
        }

        val ok = kotlinx.coroutines.withTimeoutOrNull(15000) { created.await() } ?: false
        if (!ok) return false

        val becameGo = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < 20000) {
            val infoDef = kotlinx.coroutines.CompletableDeferred<WifiP2pInfo>()
            withContext(Dispatchers.Main) {
                mgr.requestConnectionInfo(ch) { i ->
                    infoDef.complete(i)
                }
            }
            val info = kotlinx.coroutines.withTimeoutOrNull(3000) { infoDef.await() }
            if (info != null && info.groupFormed && info.isGroupOwner) {
                groupCreated = true
                becameGo.complete(true)
                break
            }
            delay(500)
        }
        return becameGo.getCompletedOrNull() ?: false
    }

    private fun connectToPeer(device: WifiP2pDevice) {
        if (!ensureWifiEnabledOrPrompt()) return
        if (!ensureLocationEnabledOrPrompt()) return

        val mgr = wifiP2pManager ?: return
        val ch = wifiChannel ?: return

        binding.tvConnectionStatus.text = "Connecting to ${device.deviceName ?: device.deviceAddress}..."
        binding.tvStatus.text = "Establishing Wi‑Fi Direct connection..."

        val cfg = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            wps.setup = WpsInfo.PBC
            groupOwnerIntent = 0
        }

        mgr.connect(ch, cfg, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                binding.tvStatus.text = "Connect requested. Waiting for link..."
            }

            override fun onFailure(reason: Int) {
                showError("Connect failed (reason=$reason)")
            }
        })
    }

    private suspend fun ensureClientSocket(info: WifiP2pInfo) {
        if (dataSocket != null && runCatching { dataSocket!!.isConnected }.getOrDefault(false)) return

        val host = info.groupOwnerAddress?.hostAddress ?: return
        var lastErr: Exception? = null
        for (attempt in 1..8) {
            try {
                withContext(Dispatchers.Main) {
                    binding.tvConnectionStatus.text = "Connected. Opening data channel... ($attempt/8)"
                }
                val sock = Socket()
                sock.tcpNoDelay = true
                sock.connect(InetSocketAddress(host, WIFI_PORT), 12000)
                dataSocket = sock
                withContext(Dispatchers.Main) {
                    binding.tvConnectionStatus.text = "Data channel ready"
                    startSenderFlow()
                }
                return
            } catch (e: Exception) {
                lastErr = e
                try { dataSocket?.close() } catch (_: Exception) {}
                dataSocket = null
                delay(1000L * attempt)
            }
        }
        withContext(Dispatchers.Main) {
            showError("Failed to open data channel: ${lastErr?.message}")
        }
    }

    private fun startTcpServerAccept() {
        acceptJob?.cancel()
        acceptJob = lifecycleScope.launch(Dispatchers.IO) {
            try {
                try { serverSocket?.close() } catch (_: Exception) {}
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(WIFI_PORT))
                }

                while (isActive) {
                    withContext(Dispatchers.Main) {
                        binding.tvConnectionStatus.text = "Waiting for sender (data channel)..."
                    }
                    val sock = serverSocket?.accept() ?: break
                    sock.tcpNoDelay = true
                    dataSocket = sock
                    withContext(Dispatchers.Main) {
                        binding.tvConnectionStatus.text = "Sender connected"
                        startReceiverFlow()
                    }
                    break
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Server error: ${e.message}")
                }
            }
        }
    }

    private fun startSenderFlow() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                performSenderFlow()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showError("Sender flow failed: ${e.message}")
                }
            }
        }
    }

    private fun startReceiverFlow() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
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
        sendNetData(package1)
        withContext(Dispatchers.Main) { binding.progressBar.progress = 30 }

        val package2Bundle = receiveNetData()
        val third = RustyCrypto.hybridSenderThird(package2Bundle) as Array<*>
        val package3 = third[0] as ByteArray
        finalSharedSecret = third[1] as ByteArray
        sendNetData(package3)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Encrypting & Sending File..."
        }

        val input = resolveInputFile(selectedFileUri!!) ?: throw IOException("Cannot access file")
        val sidecarPqrypt = File("${input.path}.pqrypt")
        val sidecarPqrypt2 = File("${input.path}.pqrypt2")
        val sidecarEncrypted = File("${input.path}.encrypted")
        val hadPqrypt = sidecarPqrypt.exists()
        val hadPqrypt2 = sidecarPqrypt2.exists()
        val hadEncrypted = sidecarEncrypted.exists()

        try {
            val originalFileName = getFileName(selectedFileUri!!) ?: "unknown_file"
            sendFileName(originalFileName)
            sendEncryptedFileStream(input.path)
        } finally {
            try {
                if (!hadPqrypt && sidecarPqrypt.exists()) sidecarPqrypt.delete()
            } catch (_: Exception) {}
            try {
                if (!hadPqrypt2 && sidecarPqrypt2.exists()) sidecarPqrypt2.delete()
            } catch (_: Exception) {}
            try {
                if (!hadEncrypted && sidecarEncrypted.exists()) sidecarEncrypted.delete()
            } catch (_: Exception) {}
            try { input.temp?.delete() } catch (_: Exception) {}
        }

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            binding.tvProgressText.text = "100%"
            showSuccess("File sent successfully")
        }
    }

    private suspend fun performReceiverFlow() {
        val treeUri = pickedFolderUri ?: throw IOException("No destination folder selected")

        withContext(Dispatchers.Main) {
            binding.llProgress.visibility = View.VISIBLE
            binding.tvProgressTitle.text = "Performing Key Exchange..."
            binding.progressBar.progress = 10
        }

        val package1 = receiveNetData()
        val package2Bundle = RustyCrypto.hybridReceiverDual(package1)
        sendNetData(package2Bundle)
        withContext(Dispatchers.Main) { binding.progressBar.progress = 40 }

        val package3 = receiveNetData()
        finalSharedSecret = RustyCrypto.hybridReceiverFinalDual(package3)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 60
            binding.tvProgressTitle.text = "Receiving and Decrypting File..."
        }

        val originalFileName = receiveFileName()
        val out = receiveAndDecryptFileStream(originalFileName, treeUri)

        withContext(Dispatchers.Main) {
            binding.progressBar.progress = 100
            binding.tvProgressTitle.text = "Transfer Complete!"
            binding.tvProgressText.text = "100%"
            showSuccess("File received")
            binding.tvStatus.text = "Saved: $out"
        }
    }

    private fun currentInputStream(): InputStream {
        return dataSocket?.getInputStream() ?: throw IOException("No active transport")
    }

    private fun currentOutputStream(): OutputStream {
        return dataSocket?.getOutputStream() ?: throw IOException("No active transport")
    }

    private fun sendNetData(data: ByteArray?) {
        if (data == null) throw IOException("Cannot send null data")
        val out = currentOutputStream()
        val lengthBytes = ByteArray(4)
        lengthBytes[0] = (data.size shr 24).toByte()
        lengthBytes[1] = (data.size shr 16).toByte()
        lengthBytes[2] = (data.size shr 8).toByte()
        lengthBytes[3] = data.size.toByte()
        out.write(lengthBytes)
        out.write(data)
        out.flush()
    }

    private fun receiveNetData(): ByteArray {
        val inputStream = currentInputStream()
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

        if (length <= 0 || length > 10 * 1024 * 1024) throw IOException("Invalid data length: $length")

        val data = ByteArray(length)
        totalRead = 0
        while (totalRead < length) {
            val read = inputStream.read(data, totalRead, length - totalRead)
            if (read == -1) throw IOException("Connection closed while reading data")
            totalRead += read
        }
        return data
    }

    private fun sendFileName(fileName: String) {
        val nameBytes = fileName.toByteArray(Charsets.UTF_8)
        val lengthBytes = ByteArray(4)
        lengthBytes[0] = (nameBytes.size shr 24).toByte()
        lengthBytes[1] = (nameBytes.size shr 16).toByte()
        lengthBytes[2] = (nameBytes.size shr 8).toByte()
        lengthBytes[3] = nameBytes.size.toByte()
        val out = currentOutputStream()
        out.write(lengthBytes)
        out.write(nameBytes)
        out.flush()
    }

    private fun receiveFileName(): String {
        val inputStream = currentInputStream()
        val lengthBuffer = ByteArray(4)
        var total = 0
        while (total < 4) {
            val r = inputStream.read(lengthBuffer, total, 4 - total)
            if (r == -1) throw IOException("Connection closed while reading filename length")
            total += r
        }
        val nameLength = ((lengthBuffer[0].toInt() and 0xFF) shl 24) or
            ((lengthBuffer[1].toInt() and 0xFF) shl 16) or
            ((lengthBuffer[2].toInt() and 0xFF) shl 8) or
            (lengthBuffer[3].toInt() and 0xFF)
        if (nameLength <= 0 || nameLength > 4096) throw IOException("Invalid filename length")
        val nameData = ByteArray(nameLength)
        total = 0
        while (total < nameLength) {
            val r = inputStream.read(nameData, total, nameLength - total)
            if (r == -1) throw IOException("Connection closed while reading filename")
            total += r
        }
        return String(nameData, Charsets.UTF_8)
    }

    private suspend fun sendEncryptedFileStream(inputPath: String) {
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
        var sentBytes = 0L
        var lastProgress = System.currentTimeMillis()
        val watchdog = kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(5000)
                if (System.currentTimeMillis() - lastProgress > 30000) {
                    Log.e(TAG, "Send stalled >30s; aborting transport")
                    try { dataSocket?.close() } catch (_: Exception) {}
                    break
                }
            }
        }
        try {
            while (true) {
                val read = src.read(buf)
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
            }
            out.write(byteArrayOf(0, 0, 0, 0))
            out.flush()
            val encResult = encJob.await()
            if (encResult != RustyCrypto.CRYPTO_SUCCESS) {
                throw IOException("Encryption failed (code=$encResult)")
            }
        } finally {
            watchdog.cancel()
            try { src.close() } catch (_: Exception) {}
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
        var lastProgress = System.currentTimeMillis()
        val watchdog = kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(5000)
                if (System.currentTimeMillis() - lastProgress > 30000) {
                    Log.e(TAG, "Recv stalled >30s; aborting transport")
                    try { dataSocket?.close() } catch (_: Exception) {}
                    break
                }
            }
        }

        try {
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
        } finally {
            watchdog.cancel()
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

    private fun openFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        filePickerLauncher.launch(intent)
    }

    private fun launchPickFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        folderPickerLauncher.launch(intent)
    }

    private fun resolveInputFile(uri: Uri): InputRef? {
        return try {
            if (uri.scheme == "content") {
                val tempFile = File.createTempFile("share_", ".tmp", cacheDir)
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                InputRef(tempFile.absolutePath, tempFile)
            } else {
                val p = uri.path ?: return null
                InputRef(p, null)
            }
        } catch (_: Exception) {
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

    private fun showError(message: String) {
        binding.tvStatus.text = "Error: $message"
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun showSuccess(message: String) {
        binding.tvStatus.text = message
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun isWifiEnabled(): Boolean {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return wm.isWifiEnabled
    }

    private fun ensureWifiEnabledOrPrompt(): Boolean {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        if (wm.isWifiEnabled) return true

        AlertDialog.Builder(this)
            .setTitle("Wi‑Fi required")
            .setMessage("Turn on Wi‑Fi to use Wi‑Fi Direct.")
            .setPositiveButton("Open Wi‑Fi Settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
            }
            .setNegativeButton("Cancel", null)
            .show()
        return false
    }

    private fun isLocationEnabled(): Boolean {
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return lm.isProviderEnabled(LocationManager.GPS_PROVIDER) || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
    }

    private fun ensureLocationEnabledOrPrompt(): Boolean {
        if (isLocationEnabled()) return true
        AlertDialog.Builder(this)
            .setTitle("Location required")
            .setMessage("Enable Location to improve Wi‑Fi Direct discovery and connection.")
            .setPositiveButton("Open Settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            }
            .setNegativeButton("Cancel", null)
            .show()
        return false
    }

    private fun ensureBatteryOptimizationsIgnoredOrPrompt() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return

        AlertDialog.Builder(this)
            .setTitle("Disable battery optimizations")
            .setMessage("To keep Wi‑Fi Direct stable, allow PQrypt to run without battery optimizations.")
            .setPositiveButton("Allow") { _, _ ->
                try {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                } catch (_: Exception) {
                    try {
                        startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    } catch (_: Exception) {}
                }
            }
            .setNegativeButton("Later", null)
            .show()
    }

    private fun openAppSettings() {
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:$packageName")
                }
            )
        } catch (_: Exception) {}
    }

    private fun acquireLocks() {
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (wifiLock == null) {
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "PQrypt:WiFiDirect")
            }
            if (wifiLock?.isHeld != true) {
                wifiLock?.acquire()
            }
        } catch (_: Exception) {}

        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            if (wakeLock == null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PQrypt:WiFiDirect")
            }
            if (wakeLock?.isHeld != true) {
                wakeLock?.acquire(10 * 60 * 1000L)
            }
        } catch (_: Exception) {}
    }

    private fun releaseLocks() {
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Exception) {}
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
    }

    private fun cleanupP2pGroup() {
        if (!permsOk) return
        if (!groupCreated) return
        val mgr = wifiP2pManager ?: return
        val ch = wifiChannel ?: return
        try {
            mgr.removeGroup(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.d(TAG, "removeGroup success")
                    groupCreated = false
                }

                override fun onFailure(reason: Int) {
                    Log.d(TAG, "removeGroup failed reason=$reason")
                    groupCreated = false
                }
            })
        } catch (_: Exception) {}
    }

    companion object {
        private const val TAG = "PQrypt"
        private const val WIFI_PORT = 8988
        private const val PERMISSIONS_REQUEST_CODE = 310
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private fun <T> kotlinx.coroutines.CompletableDeferred<T>.getCompletedOrNull(): T? {
        return try {
            getCompleted()
        } catch (_: Exception) {
            null
        }
    }
}
