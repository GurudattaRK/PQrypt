package com.pqrypt.app // Package namespace for this Kotlin file

import android.app.assist.AssistStructure // Provides a snapshot of the UI structure for autofill
import android.os.Build // Access to SDK version constants
import android.os.CancellationSignal // Allows cancelling long-running operations
import android.os.Handler // Schedules work on a thread's message queue
import android.os.Looper // Provides the message loop for a thread
import android.service.autofill.* // Autofill framework classes (service, requests, responses)
import android.text.InputType // Input type flags for identifying password fields
import android.view.View // Base class for UI widgets; used for autofill hints
import android.view.autofill.AutofillId // Identifier for a field that can be autofilled
import android.view.autofill.AutofillValue // Value container for autofill data
import android.widget.RemoteViews // Lightweight views used in datasets/shows
import androidx.annotation.RequiresApi // Annotation to require a minimum API level
import java.util.* // Utility classes (used for Arrays.fill)

@RequiresApi(Build.VERSION_CODES.O) // Ensure this service runs only on API 26+
class PQryptAutofillService : AutofillService() { // Service that supplies autofill data to the system

    companion object { // Static-like container for shared state and helpers
        private const val TAG = "PQryptAutofill" // Log tag for this class
        private var pendingPassword: String? = null // Temporarily stored password to inject via autofill
        private var clearPasswordHandler: Handler? = null // Handler for scheduling password clearing
        private var clearPasswordRunnable: Runnable? = null // Runnable that clears the pending password
        
        fun setPasswordForAutofill(password: String) { // Store a password for later autofill use
            pendingPassword = password // Save provided password in memory (temporary)
            // Log.d(TAG, "Password set for autofill - Length: ${password.length} characters") // Log sanitized info
            
            // Initialize handler if needed
            if (clearPasswordHandler == null) { // Create handler on main thread if absent
                clearPasswordHandler = Handler(Looper.getMainLooper()) // Bind to main Looper
            }
            
            // Clear any existing timer
            clearPasswordRunnable?.let { clearPasswordHandler?.removeCallbacks(it) } // Cancel prior scheduled clear
            
            // Start 60-second auto-clear timer
            clearPasswordRunnable = Runnable { // Define action to clear password later
                clearPendingPassword() // Wipe stored password
                // Log.d(TAG, "Password auto-cleared after 60 seconds") // Audit log for auto-clear
            }
            clearPasswordHandler?.postDelayed(clearPasswordRunnable!!, 60000) // Schedule clear after 60s
        }
        
        fun clearPendingPassword() { // Immediately clear any stored password and timers
            // Clear timer
            clearPasswordRunnable?.let { clearPasswordHandler?.removeCallbacks(it) } // Cancel scheduled runnable
            
            // Clear password and overwrite memory
            pendingPassword?.let { password -> // If a password exists
                val charArray = password.toCharArray() // Copy to mutable char array
                Arrays.fill(charArray, '\u0000') // Overwrite chars to reduce memory residue
                // Log.d(TAG, "Password memory overwritten - ${charArray.size} characters zeroed") // Log wipe
            }
            pendingPassword = null // Remove strong reference to the password
            // Log.d(TAG, "Pending password cleared and nullified") // Confirm cleared state
        }
        
        // Debug method to verify if password is available for autofill
        fun isPasswordAvailable(): Boolean { // Return whether a password is currently stored
            val available = pendingPassword != null // True if not null
            // Log.d(TAG, "Password availability check: $available") // Log current availability
            return available // Expose status to callers
        }
        
        // Debug method to get password length without exposing the actual password
        fun getPasswordLength(): Int { // Computes the stored password length safely
            val length = pendingPassword?.length ?: 0 // 0 if none
            // Log.d(TAG, "Current password length: $length") // Log the length for diagnostics
            return length // Provide information without revealing content
        }
    }

    override fun onFillRequest(
        request: FillRequest, // Incoming request containing context and structure
        cancellationSignal: CancellationSignal, // Signal to cancel processing
        callback: FillCallback // Callback to return a response
    ) { // Called by the system to obtain autofill data
        // Log.d(TAG, " onFillRequest called") // Trace entry
        
        val structure = request.fillContexts.lastOrNull()?.structure // Get latest AssistStructure snapshot
        if (structure == null) { // If no UI structure available
            // Log.w(TAG, " No structure found") // Warn and
            callback.onSuccess(null) // return no datasets
            return // Exit early
        }

        if (pendingPassword == null) { // Nothing to autofill if no stored password
            // Log.d(TAG, " No pending password available") // Log and
            callback.onSuccess(null) // return no datasets
            return // Exit
        }

        // Log.d(TAG, " Pending password available: ${pendingPassword!!.length} characters") // Password exists; report length
        
        val passwordFields = findPasswordFields(structure) // Scan structure to locate password fields
        // Log.d(TAG, " Found ${passwordFields.size} password fields") // Log count
        
        if (passwordFields.isEmpty()) { // If no suitable targets
            // Log.d(TAG, " No password fields detected") // Inform and
            callback.onSuccess(null) // send empty response
            return // Exit
        }

        try { // Build a response with datasets for each field
            val responseBuilder = FillResponse.Builder() // Container for datasets and actions
            
            // Create dataset for each password field
            passwordFields.forEachIndexed { index, passwordField -> // Iterate over targets
                // Log.d(TAG, " Creating dataset for field $index: $passwordField") // Trace dataset creation
                
                val dataset = Dataset.Builder() // Build a dataset representing a fill option
                    .setValue(
                        passwordField, // Target field ID to fill
                        AutofillValue.forText(pendingPassword), // Provide the password as text value
                        createRemoteViews(" Use PQrypt Password") // UI label shown in the autofill dropdown
                    )
                    .build() // Finalize dataset
                
                responseBuilder.addDataset(dataset) // Add dataset to the response
            }

            val response = responseBuilder.build() // Build the final response
            callback.onSuccess(response) // Send response back to the system
            // Log.d(TAG, " Fill response sent successfully") // Trace success
            
        } catch (e: Exception) { // Defensive: catch and report any exceptions
            // Log.e(TAG, " Error creating fill response", e) // Log error with stacktrace
            callback.onFailure("Failed to create autofill response: ${e.message}") // Notify system of failure
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) { // Invoked to persist user data (unused)
        // Log.d(TAG, "onSaveRequest called - not implemented for security") // Explicitly not saving credentials
        callback.onSuccess() // Acknowledge the request without action
    }

    private fun findPasswordFields(structure: AssistStructure): List<AutofillId> { // Walk the UI tree and collect password fields
        val passwordFields = mutableListOf<AutofillId>() // Accumulator for field IDs
        
        for (i in 0 until structure.windowNodeCount) { // Iterate over all window nodes
            val windowNode = structure.getWindowNodeAt(i) // Access window node by index
            findPasswordFieldsInNode(windowNode.rootViewNode, passwordFields) // Recurse from each root node
        }
        
        return passwordFields // Return collected targets
    }

    private fun findPasswordFieldsInNode(node: AssistStructure.ViewNode, passwordFields: MutableList<AutofillId>) { // DFS to detect password fields
        val autofillHints = node.autofillHints // Hints set by apps to indicate field purpose
        val inputType = node.inputType // Type flags for text/password inputs
        val className = node.className // Class name of the view (unused but useful for debugging)
        val viewId = node.idEntry // Resource entry name of the view ID if available
        
        // Multiple detection methods
        val isPasswordField = when { // Combine heuristics to identify password fields
            // 1. Autofill hints
            autofillHints?.any { hint -> // Check provided hints for password
                hint.equals("password", ignoreCase = true) ||
                hint.equals(View.AUTOFILL_HINT_PASSWORD, ignoreCase = true)
            } == true -> true
            
            // 2. Input type flags  
            (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0 -> true // Obfuscated text password
            (inputType and InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) != 0 -> true // Visible password field
            (inputType and InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0 -> true // Web password field
            
            // 3. View ID contains password
            viewId?.contains("password", ignoreCase = true) == true -> true // Common naming convention
            viewId?.contains("pass", ignoreCase = true) == true -> true // Abbreviation check
            viewId?.contains("pwd", ignoreCase = true) == true -> true // Another common abbreviation
            
            // 4. HTML input type (for WebViews)
            node.htmlInfo?.attributes?.any { attr -> // Inspect HTML attributes
                attr.first == "type" && attr.second.equals("password", ignoreCase = true)
            } == true -> true
            
            else -> false // Not a password field
        }
        
        if (isPasswordField && node.autofillId != null) { // Ensure we have a targetable field
            passwordFields.add(node.autofillId!!) // Collect the field's autofill ID
            // Log.d(TAG, " Found password field - ID: ${node.autofillId}, ViewID: $viewId, InputType: $inputType") // Log detection
        } else if (node.autofillId != null) { // If not a password, still log for debugging
            // Log.d(TAG, " Skipped field - ID: ${node.autofillId}, ViewID: $viewId, InputType: $inputType, Hints: ${autofillHints?.joinToString()}") // Trace skipped node
        }
        
        // Recursively check children
        for (i in 0 until node.childCount) { // Depth-first traversal
            findPasswordFieldsInNode(node.getChildAt(i), passwordFields) // Recurse into child
        }
    }

    private fun createRemoteViews(text: String): RemoteViews { // Build a simple list item to show in suggestions
        val remoteViews = RemoteViews(packageName, android.R.layout.simple_list_item_1) // Use built-in single-line layout
        remoteViews.setTextViewText(android.R.id.text1, text) // Set display label
        remoteViews.setTextColor(android.R.id.text1, android.graphics.Color.BLACK) // Ensure text is readable
        return remoteViews // Provide to Dataset.Builder
    }
}
