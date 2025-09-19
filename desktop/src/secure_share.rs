use std::fs;
use crate::rusty_api;

// State management for Secure Share
pub struct SecureShareState {
    pub pqc_state: PqcState,
    pub temp_text_file: Option<String>,
    pub is_sender: bool,
    pub mode: String, // "text" or "file"
    pub step: u8, // Current step in the process
    pub key_output_dir: String, // Directory for key files
}

pub struct PqcState {
    sender_state: Option<rusty_api::hybrid::HybridSenderState>,
    receiver_state: Option<rusty_api::hybrid::HybridReceiverState>,
    final_shared_secret: Option<[u8; 128]>, // final 128-byte secret
    pub step: u8,
}

impl PqcState {
    fn new() -> Self {
        Self {
            sender_state: None,
            receiver_state: None,
            final_shared_secret: None,
            step: 0,
        }
    }
}

impl SecureShareState {
    pub fn new() -> Self {
        // Use executable directory by default
        let default_dir = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".to_string());
            
        Self {
            pqc_state: PqcState::new(),
            temp_text_file: None,
            is_sender: false,
            mode: "file".to_string(),
            step: 0,
            key_output_dir: default_dir,
        }
    }
    
    pub fn reset(&mut self) {
        self.pqc_state = PqcState::new();
        if let Some(temp_file) = &self.temp_text_file {
            let _ = fs::remove_file(temp_file);
        }
        self.temp_text_file = None;
        self.is_sender = false;
        self.mode = "file".to_string();
        self.step = 0;
        // Keep the key_output_dir
    }
    
    pub fn set_key_output_dir(&mut self, dir: &str) {
        self.key_output_dir = dir.to_string();
    }
    
    pub fn set_mode(&mut self, mode: &str) {
        self.mode = mode.to_string();
    }
    
    pub fn set_sender(&mut self, is_sender: bool) {
        self.is_sender = is_sender;
    }
}

pub struct SecureShareResult {
    pub success: bool,
    pub message: String,
    pub file_path: Option<String>,
}

impl SecureShareResult {
    pub fn success(message: &str, file_path: Option<String>) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            file_path,
        }
    }
    
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            file_path: None,
        }
    }
}

pub fn start_sender(state: &mut SecureShareState, text_content: Option<&str>, file_path: Option<&str>) -> SecureShareResult {
    state.is_sender = true;
    state.step = 1;
    
    // Handle text mode - write text to temporary file
    if state.mode == "text" {
        if let Some(text) = text_content {
            if text.is_empty() {
                return SecureShareResult::error("Please enter text to share first");
            }
            
            let temp_filename = format!("secure_share_text_{}.txt", 
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs());
            
            let temp_file_path = std::path::Path::new(&state.key_output_dir).join(&temp_filename);
                    
            match fs::write(&temp_file_path, text) {
                Ok(_) => {
                    state.temp_text_file = Some(temp_file_path.to_string_lossy().to_string());
                    return start_pqc_exchange(state, Some(temp_file_path.to_string_lossy().to_string()));
                },
                Err(e) => {
                    return SecureShareResult::error(&format!("Error saving text: {}", e));
                }
            }
        } else {
            return SecureShareResult::error("No text content provided for text sharing mode");
        }
    } else {
        // File mode - check if file is provided
        if let Some(path) = file_path {
            if path.is_empty() {
                return SecureShareResult::error("Please select a file to share first");
            }
            return start_pqc_exchange(state, Some(path.to_string()));
        } else {
            return SecureShareResult::error("No file path provided for file sharing mode");
        }
    }
}

fn start_pqc_exchange(state: &mut SecureShareState, _file_path: Option<String>) -> SecureShareResult {
    // Start PQC key exchange as sender
    let (sender_bundle, sender_state) = match rusty_api::pqc_4hybrid_init() {
        Ok(result) => result,
        Err(e) => {
            return SecureShareResult::error(&format!("Key exchange error: {}", e));
        }
    };
    
    state.pqc_state.sender_state = Some(sender_state);
    state.pqc_state.step = 1;
    
    let key_path = std::path::Path::new(&state.key_output_dir).join("1.key");
    match fs::write(&key_path, sender_bundle) {
        Ok(_) => {
            let full_path = key_path.canonicalize()
                .unwrap_or_else(|_| key_path.clone());
            SecureShareResult::success(
                "Step 2: Generated 1.key. Send it to the receiver.",
                Some(format!("{} - Send this to Receiver", full_path.to_string_lossy()))
            )
        }
        Err(e) => SecureShareResult::error(&format!("Error saving key: {}", e)),
    }
}

pub fn start_receiver(state: &mut SecureShareState, mode: &str) -> SecureShareResult {
    state.is_sender = false;
    state.mode = mode.to_string();
    state.step = 1;
    state.pqc_state.step = 0; // Initialize PQC state step to 0 for receiver
    SecureShareResult::success("Waiting for sender's 1.key file. Use 'Open Sender's Key' when received.", None)
}

pub fn generate_key(state: &mut SecureShareState, key_file_path: &str) -> SecureShareResult {
    generate_key_with_file_path(state, key_file_path, None)
}

pub fn generate_key_with_file_path(state: &mut SecureShareState, key_file_path: &str, file_path: Option<&str>) -> SecureShareResult {
    if key_file_path.is_empty() {
        return SecureShareResult::error("No key file path provided");
    }
    
    if state.is_sender {
        // Sender generates final key from receiver's response
        if state.pqc_state.step == 1 {
            match fs::read(key_file_path) {
                Ok(receiver_bundle) => {
                    if let Some(sender_state) = &state.pqc_state.sender_state {
                        match rusty_api::pqc_4hybrid_snd_final(&receiver_bundle, sender_state) {
                            Ok((final_shared_secret, sender_final_bundle)) => {
                                state.pqc_state.final_shared_secret = Some(final_shared_secret);
                                state.pqc_state.step = 2;
                                state.step = 3;
                                
                                let key3_path = std::path::Path::new(&state.key_output_dir).join("3.key");
                                let final_key_path = std::path::Path::new(&state.key_output_dir).join("final.key");
                                match fs::write(&key3_path, &sender_final_bundle) {
                                    Ok(_) => {
                                        // Also save final.key for encryption
                                        match fs::write(&final_key_path, &final_shared_secret) {
                                            Ok(_) => {
                                                // Debug: Print key hash for verification
                                                println!("SENDER final.key hash: {:?}", &final_shared_secret[..8]);
                                                // Clean up intermediate key files
                                                let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("1.key"));
                                                let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("2.key"));
                                                
                                                // Auto-encrypt the file now that we have final.key
                                                let encrypt_result = if state.mode == "text" {
                                                    if let Some(temp_file) = &state.temp_text_file {
                                                        encrypt_file_with_key_dir(temp_file, &state.key_output_dir)
                                                    } else {
                                                        SecureShareResult::error("No text file to encrypt")
                                                    }
                                                } else if let Some(file_to_encrypt) = file_path {
                                                    encrypt_file_with_key_dir(file_to_encrypt, &state.key_output_dir)
                                                } else {
                                                    SecureShareResult::success("Ready to encrypt file", None)
                                                };
                                                
                                                if encrypt_result.success {
                                                    let full_path = key3_path.canonicalize()
                                                        .unwrap_or_else(|_| key3_path.clone());
                                                    SecureShareResult::success(
                                                        &format!("Step 4: Generated 3.key and encrypted file! Send 3.key and encrypted file to receiver. Encrypted file: {}", 
                                                                encrypt_result.file_path.unwrap_or_default()),
                                                        Some(format!("{} - Send this to Receiver", full_path.to_string_lossy()))
                                                    )
                                                } else {
                                                    let full_path = key3_path.canonicalize()
                                                        .unwrap_or_else(|_| key3_path.clone());
                                                    SecureShareResult::success(
                                                        "Step 4: Generated 3.key. Send it to receiver, then you can encrypt.",
                                                        Some(format!("{} - Send this to Receiver", full_path.to_string_lossy()))
                                                    )
                                                }
                                            }
                                            Err(e) => SecureShareResult::error(&format!("Error saving final key: {}", e)),
                                        }
                                    }
                                    Err(e) => SecureShareResult::error(&format!("Error saving key: {}", e)),
                                }
                            }
                            Err(e) => SecureShareResult::error(&format!("Key exchange error: {}", e)),
                        }
                    } else {
                        SecureShareResult::error("No sender state available")
                    }
                }
                Err(e) => SecureShareResult::error(&format!("Error reading key: {}", e)),
            }
        } else {
            SecureShareResult::error("Invalid step for sender key generation")
        }
    } else {
        // Receiver logic
        if state.pqc_state.step == 0 {
            // Generate response to sender's initial key
            match fs::read(key_file_path) {
                Ok(sender_bundle) => {
                    match rusty_api::pqc_4hybrid_recv(&sender_bundle) {
                        Ok((receiver_bundle, receiver_state)) => {
                            state.pqc_state.receiver_state = Some(receiver_state);
                            state.pqc_state.step = 1;
                            state.step = 2;
                            
                            let key2_path = std::path::Path::new(&state.key_output_dir).join("2.key");
                            match fs::write(&key2_path, &receiver_bundle) {
                                Ok(_) => {
                                    let full_path = key2_path.canonicalize()
                                        .unwrap_or_else(|_| key2_path.clone());
                                    SecureShareResult::success(
                                        "Step 3: Generated 2.key. Send it to sender and wait for 3.key.",
                                        Some(format!("{} - Send this to Sender", full_path.to_string_lossy()))
                                    )
                                }
                                Err(e) => SecureShareResult::error(&format!("Error saving key: {}", e)),
                            }
                        }
                        Err(e) => SecureShareResult::error(&format!("Key exchange error: {}", e)),
                    }
                }
                Err(e) => SecureShareResult::error(&format!("Error reading key: {}", e)),
            }
        } else if state.pqc_state.step == 1 {
            // Finalize with sender's final key
            match fs::read(key_file_path) {
                Ok(sender_final_bundle) => {
                    if let Some(receiver_state) = &state.pqc_state.receiver_state {
                        match rusty_api::pqc_4hybrid_recv_final(&sender_final_bundle, receiver_state) {
                            Ok(final_shared_secret) => {
                                state.pqc_state.step = 2;
                                state.pqc_state.final_shared_secret = Some(final_shared_secret);
                                state.step = 3;
                                
                                let final_key_path = std::path::Path::new(&state.key_output_dir).join("final.key");
                                match fs::write(&final_key_path, &final_shared_secret) {
                                    Ok(_) => {
                                        // Debug: Print key hash for verification
                                        println!("RECEIVER final.key hash: {:?}", &final_shared_secret[..8]);
                                        // Clean up intermediate key files
                                        let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("1.key"));
                                        let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("2.key"));
                                        let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("3.key"));
                                        
                                        let full_path = final_key_path.canonicalize()
                                            .unwrap_or_else(|_| final_key_path.clone());
                                        // Auto-decrypt encrypted files
                                        let decrypt_result = auto_decrypt_encrypted_files(&state.key_output_dir, &state.mode);
                                        match decrypt_result {
                                            Ok(content) => {
                                                if state.mode == "text" && !content.is_empty() {
                                                    SecureShareResult::success(
                                                        "Key exchange complete! Text message decrypted.",
                                                        Some(content)
                                                    )
                                                } else {
                                                    SecureShareResult::success(
                                                        "Key exchange complete! File decrypted.",
                                                        Some(content)
                                                    )
                                                }
                                            }
                                            Err(e) => {
                                                SecureShareResult::success(
                                                    &format!("Key exchange complete! {}", e),
                                                    Some(format!("{} - Key ready for decryption", full_path.to_string_lossy()))
                                                )
                                            }
                                        }
                                    }
                                    Err(e) => SecureShareResult::error(&format!("Error saving final key: {}", e)),
                                }
                            }
                            Err(e) => SecureShareResult::error(&format!("Finalize error: {}", e)),
                        }
                    } else {
                        SecureShareResult::error("No receiver state available")
                    }
                }
                Err(e) => SecureShareResult::error(&format!("Error reading final key: {}", e)),
            }
        } else {
            SecureShareResult::error("Invalid step for receiver key generation")
        }
    }
}

pub fn encrypt_file(file_path: &str) -> SecureShareResult {
    encrypt_file_with_key_dir(file_path, ".")
}

pub fn encrypt_file_with_key_dir(file_path: &str, key_dir: &str) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No file to encrypt");
    }
    
    // Use final.key for encryption
    let final_key_path = std::path::Path::new(key_dir).join("final.key");
    match fs::read(&final_key_path) {
        Ok(key_data) => {
            // Ensure we use exactly 128 bytes for consistency
            let mut secret = [0u8; 128];
            let copy_len = std::cmp::min(key_data.len(), 128);
            secret[..copy_len].copy_from_slice(&key_data[..copy_len]);
            let secret = &secret;
            
            // Generate encrypted file in the key directory
            let file_name = std::path::Path::new(file_path)
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("file"))
                .to_string_lossy();
            let suggested_output_path = std::path::Path::new(key_dir)
                .join(format!("{}.encrypted", file_name));
            let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());
            
            match rusty_api::api::encrypt_file_pqrypt2(file_path, &output_path, secret) {
                Ok(_) => {
                    let full_output_path = std::path::Path::new(&output_path)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                    SecureShareResult::success(
                        "File encrypted successfully! Send this encrypted file to receiver.",
                        Some(full_output_path.to_string_lossy().to_string())
                    )
                }
                Err(e) => SecureShareResult::error(&format!("Encryption error: {}", e)),
            }
        }
        Err(e) => SecureShareResult::error(&format!("Error reading final.key: {}", e)),
    }
}

pub fn decrypt_file(file_path: &str, mode: &str) -> SecureShareResult {
    decrypt_file_with_key_dir(file_path, mode, ".")
}

pub fn decrypt_file_with_key_dir(file_path: &str, mode: &str, key_dir: &str) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No encrypted file selected");
    }
    
    // Use final.key for decryption
    let final_key_path = std::path::Path::new(key_dir).join("final.key");
    match fs::read(&final_key_path) {
        Ok(key_data) => {
            // Ensure we use exactly 128 bytes for consistency
            let mut secret = [0u8; 128];
            let copy_len = std::cmp::min(key_data.len(), 128);
            secret[..copy_len].copy_from_slice(&key_data[..copy_len]);
            let secret = &secret;
            
            // Generate output path in the key directory, removing .encrypted extension
            let original_name = if file_path.ends_with(".encrypted") {
                std::path::Path::new(file_path)
                    .file_name()
                    .unwrap_or(std::ffi::OsStr::new("file"))
                    .to_string_lossy()
                    .trim_end_matches(".encrypted")
                    .to_string()
            } else {
                format!("{}.decrypted", 
                    std::path::Path::new(file_path)
                        .file_name()
                        .unwrap_or(std::ffi::OsStr::new("file"))
                        .to_string_lossy())
            };
            
            let suggested_output_path = std::path::Path::new(key_dir).join(&original_name);
            let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());
            
            match rusty_api::api::decrypt_file_pqrypt2(file_path, &output_path, secret) {
                Ok(_) => {
                    let full_output_path = std::path::Path::new(&output_path)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                    
                    // If text mode, read the decrypted file content
                    if mode == "text" {
                        match fs::read_to_string(&output_path) {
                            Ok(text_content) => {
                                SecureShareResult::success("Text message decrypted successfully!", Some(text_content))
                            }
                            Err(e) => SecureShareResult::error(&format!("Error reading decrypted text: {}", e)),
                        }
                    } else {
                        SecureShareResult::success(
                            "File decrypted successfully!",
                            Some(full_output_path.to_string_lossy().to_string())
                        )
                    }
                }
                Err(e) => SecureShareResult::error(&format!("Decryption failed: {}", e)),
            }
        }
        Err(e) => SecureShareResult::error(&format!("Error reading final.key: {}", e)),
    }
}

// Helper function to generate unique filename with "_copy" suffix for duplicates
fn generate_unique_filename(base_path: &str) -> String {
    let path = std::path::Path::new(base_path);
    
    if !path.exists() {
        return base_path.to_string();
    }
    
    // Extract filename and extension
    let parent = path.parent().unwrap_or(std::path::Path::new(""));
    let stem = path.file_stem().unwrap_or(std::ffi::OsStr::new("file")).to_string_lossy();
    let extension = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    
    // Try with "_copy" suffix
    for i in 1..=100 {
        let copy_suffix = "_copy".repeat(i);
        let new_filename = format!("{}{}{}", stem, copy_suffix, extension);
        let new_path = parent.join(&new_filename);
        
        if !new_path.exists() {
            return new_path.to_string_lossy().to_string();
        }
    }
    
    // Fallback if all attempts failed
    base_path.to_string()
}

// Auto-decrypt encrypted files in the key directory
fn auto_decrypt_encrypted_files(key_dir: &str, mode: &str) -> Result<String, String> {
    let dir_path = std::path::Path::new(key_dir);
    
    // Look for .encrypted files in the directory
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(e) => return Err(format!("Cannot read directory: {}", e)),
    };
    
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("encrypted") {
                let file_path = path.to_string_lossy().to_string();
                
                // Try to decrypt this file
                let result = decrypt_file_with_key_dir(&file_path, mode, key_dir);
                if result.success {
                    if let Some(content) = result.file_path {
                        return Ok(content);
                    }
                }
            }
        }
    }
    
    Err("No encrypted files found to decrypt".to_string())
}
