package com.pqrypt.app

import android.net.wifi.p2p.WifiP2pDevice
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class WifiDirectDeviceAdapter(
    private val devices: List<WifiP2pDevice>,
    private val onDeviceClick: (WifiP2pDevice) -> Unit
) : RecyclerView.Adapter<WifiDirectDeviceAdapter.DeviceViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DeviceViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_wifi_direct_device, parent, false)
        return DeviceViewHolder(view)
    }

    override fun onBindViewHolder(holder: DeviceViewHolder, position: Int) {
        val device = devices[position]
        holder.bind(device)
        holder.itemView.setOnClickListener { onDeviceClick(device) }
    }

    override fun getItemCount(): Int = devices.size

    class DeviceViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val tvName: TextView = itemView.findViewById(R.id.tv_device_name)
        private val tvAddr: TextView = itemView.findViewById(R.id.tv_device_address)
        private val tvStatus: TextView = itemView.findViewById(R.id.tv_device_status)

        fun bind(device: WifiP2pDevice) {
            tvName.text = device.deviceName ?: "Unknown"
            tvAddr.text = device.deviceAddress ?: ""
            tvStatus.text = statusText(device.status)
        }

        private fun statusText(status: Int): String {
            return when (status) {
                WifiP2pDevice.AVAILABLE -> "Available"
                WifiP2pDevice.INVITED -> "Invited"
                WifiP2pDevice.CONNECTED -> "Connected"
                WifiP2pDevice.FAILED -> "Failed"
                WifiP2pDevice.UNAVAILABLE -> "Unavailable"
                else -> "Unknown"
            }
        }
    }
}
