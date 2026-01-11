use std::fs;
use zeroize::Zeroize;

use crate::rusty_api;

pub struct SecureShareState {
    pub pqc_state: PqcState,
    pub temp_text_file: Option<String>,
    pub is_sender: bool,
    pub mode: String,
    pub step: u8,
    pub key_output_dir: String,
}

pub struct PqcState {
    sender_state: Option<rusty_api::hybrid::HybridSenderState>,
    receiver_state: Option<rusty_api::hybrid::HybridReceiverState>,
    pub step: u8,
}

impl PqcState {
    #[inline(always)]
    fn new() -> Self {
        Self {
            sender_state: None,
            receiver_state: None,
            step: 0,
        }
    }
}

impl SecureShareState {
    #[inline(always)]
    pub fn new() -> Self {
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

    #[inline(always)]
    pub fn reset(&mut self) {
        self.pqc_state = PqcState::new();
        if let Some(temp_file) = &self.temp_text_file {
            let _ = fs::remove_file(temp_file);
        }
        self.temp_text_file = None;
        self.is_sender = false;
        self.mode = "file".to_string();
        self.step = 0;
    }

    #[inline(always)]
    pub fn set_key_output_dir(&mut self, dir: &str) {
        self.key_output_dir = dir.to_string();
    }

    #[inline(always)]
    pub fn set_mode(&mut self, mode: &str) {
        self.mode = mode.to_string();
    }

    #[inline(always)]
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
    #[inline(always)]
    pub fn success(message: &str, file_path: Option<String>) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            file_path,
        }
    }

    #[inline(always)]
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            file_path: None,
        }
    }
}

#[inline(always)]
pub fn start_sender(state: &mut SecureShareState, text_content: Option<&str>, file_path: Option<&str>) -> SecureShareResult {
    state.is_sender = true;
    state.step = 1;

    if state.mode == "text" {
        let Some(text) = text_content else {
            return SecureShareResult::error("No text content provided for text sharing mode");
        };
        if text.is_empty() {
            return SecureShareResult::error("Please enter text to share first");
        }

        let temp_filename = format!(
            "secure_share_text_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        let temp_file_path = std::path::Path::new(&state.key_output_dir).join(&temp_filename);
        match fs::write(&temp_file_path, text) {
            Ok(_) => {
                state.temp_text_file = Some(temp_file_path.to_string_lossy().to_string());
                start_pqc_exchange(state)
            }
            Err(e) => SecureShareResult::error(&format!("Error saving text: {e}")),
        }
    } else {
        let Some(path) = file_path else {
            return SecureShareResult::error("No file path provided for file sharing mode");
        };
        if path.is_empty() {
            return SecureShareResult::error("Please select a file to share first");
        }
        start_pqc_exchange(state)
    }
}

#[inline(always)]
fn start_pqc_exchange(state: &mut SecureShareState) -> SecureShareResult {
    let (pkg1, sender_state) = match rusty_api::hybrid::hybrid_sender_init() {
        Ok(v) => v,
        Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
    };

    state.pqc_state.sender_state = Some(sender_state);
    state.pqc_state.step = 1;

    let key_path = std::path::Path::new(&state.key_output_dir).join("1.key");
    match fs::write(&key_path, pkg1) {
        Ok(_) => {
            let full_path = key_path.canonicalize().unwrap_or_else(|_| key_path.clone());
            SecureShareResult::success(
                "Step 1: 1.key generated! Send this file to the receiver and wait for their response",
                Some(format!("{} - Send this to Receiver", full_path.to_string_lossy())),
            )
        }
        Err(e) => SecureShareResult::error(&format!("Error saving key: {e}")),
    }
}

#[inline(always)]
pub fn start_receiver(state: &mut SecureShareState, mode: &str) -> SecureShareResult {
    state.reset();
    state.is_sender = false;
    state.mode = mode.to_string();
    state.step = 1;

    SecureShareResult::success(
        "Step 1: Wait for sender's files. Once you receive 1.key, 3.key and .pqrypt file, press 'Open Key' and select 1.key",
        None,
    )
}

pub fn generate_key_with_file_path(state: &mut SecureShareState, key_file_path: &str, file_path: Option<&str>) -> SecureShareResult {
    if key_file_path.is_empty() {
        return SecureShareResult::error("No key file path provided");
    }

    if state.is_sender {
        if state.pqc_state.step != 1 {
            return SecureShareResult::error("Invalid step for sender key generation");
        }

        let receiver_bundle = match fs::read(key_file_path) {
            Ok(b) => b,
            Err(e) => return SecureShareResult::error(&format!("Error reading key: {e}")),
        };

        let sender_state = match state.pqc_state.sender_state.take() {
            Some(s) => s,
            None => return SecureShareResult::error("No sender state available"),
        };

        let (pkg3, mut final_key) = match rusty_api::hybrid::hybrid_sender_third(&receiver_bundle, sender_state) {
            Ok(v) => v,
            Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
        };

        state.pqc_state.step = 2;
        state.step = 3;

        let key3_path = std::path::Path::new(&state.key_output_dir).join("3.key");
        let final_key_path = std::path::Path::new(&state.key_output_dir).join("final.key");

        if let Err(e) = fs::write(&key3_path, &pkg3) {
            final_key.zeroize();
            return SecureShareResult::error(&format!("Error saving key: {e}"));
        }

        let write_final_res = fs::write(&final_key_path, final_key.as_slice());
        final_key.zeroize();

        if let Err(e) = write_final_res {
            return SecureShareResult::error(&format!("Error saving final key: {e}"));
        }

        let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("1.key"));
        let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("2.key"));

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

        let full_path = key3_path.canonicalize().unwrap_or_else(|_| key3_path.clone());

        if encrypt_result.success {
            SecureShareResult::success(
                &format!(
                    "Step 4: Generated 3.key and encrypted file! Send 3.key and .pqrypt file to receiver. Encrypted file: {}",
                    encrypt_result.file_path.clone().unwrap_or_default()
                ),
                Some(format!("{} - Send this to Receiver", full_path.to_string_lossy())),
            )
        } else {
            SecureShareResult::success(
                "Step 4: Generated 3.key. Send it to receiver, then you can encrypt.",
                Some(format!("{} - Send this to Receiver", full_path.to_string_lossy())),
            )
        }
    } else {
        if state.pqc_state.step == 0 {
            let sender_pkg1 = match fs::read(key_file_path) {
                Ok(b) => b,
                Err(e) => return SecureShareResult::error(&format!("Error reading key: {e}")),
            };

            let (bundle2, receiver_state) = match rusty_api::hybrid::hybrid_receiver_dual(&sender_pkg1) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
            };

            state.pqc_state.receiver_state = Some(receiver_state);
            state.pqc_state.step = 1;
            state.step = 2;

            let key2_path = std::path::Path::new(&state.key_output_dir).join("2.key");
            match fs::write(&key2_path, &bundle2) {
                Ok(_) => {
                    let full_path = key2_path.canonicalize().unwrap_or_else(|_| key2_path.clone());
                    SecureShareResult::success(
                        "Step 3: Generated 2.key. Send it to sender and wait for 3.key.",
                        Some(format!("{} - Send this to Sender", full_path.to_string_lossy())),
                    )
                }
                Err(e) => SecureShareResult::error(&format!("Error saving key: {e}")),
            }
        } else if state.pqc_state.step == 1 {
            let pkg3 = match fs::read(key_file_path) {
                Ok(b) => b,
                Err(e) => return SecureShareResult::error(&format!("Error reading final key: {e}")),
            };

            let receiver_state = match state.pqc_state.receiver_state.take() {
                Some(s) => s,
                None => return SecureShareResult::error("No receiver state available"),
            };

            let mut final_key = match rusty_api::hybrid::hybrid_receiver_final_dual(&pkg3, receiver_state) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Finalize error: {e}")),
            };

            state.pqc_state.step = 2;
            state.step = 3;

            let final_key_path = std::path::Path::new(&state.key_output_dir).join("final.key");
            let write_res = fs::write(&final_key_path, final_key.as_slice());
            final_key.zeroize();

            match write_res {
                Ok(_) => {
                    let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("1.key"));
                    let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("2.key"));
                    let _ = fs::remove_file(std::path::Path::new(&state.key_output_dir).join("3.key"));

                    let decrypt_result = auto_decrypt_pqrypt_files(&state.key_output_dir, &state.mode);
                    match decrypt_result {
                        Ok(content) => {
                            if state.mode == "text" && !content.is_empty() {
                                SecureShareResult::success("Key exchange complete! Text message decrypted.", Some(content))
                            } else {
                                SecureShareResult::success("Key exchange complete! File decrypted.", Some(content))
                            }
                        }
                        Err(e) => {
                            let full_path = final_key_path
                                .canonicalize()
                                .unwrap_or_else(|_| final_key_path.clone());
                            SecureShareResult::success(
                                &format!("Key exchange complete! {e}"),
                                Some(format!("{} - Key ready for decryption", full_path.to_string_lossy())),
                            )
                        }
                    }
                }
                Err(e) => SecureShareResult::error(&format!("Error saving final key: {e}")),
            }
        } else {
            SecureShareResult::error("Invalid step for receiver key generation")
        }
    }
}

#[inline(always)]
pub fn encrypt_file(file_path: &str) -> SecureShareResult {
    encrypt_file_with_key_dir(file_path, ".")
}

pub fn encrypt_file_with_key_dir(file_path: &str, key_dir: &str) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No file to encrypt");
    }

    let final_key_path = std::path::Path::new(key_dir).join("final.key");
    match fs::read(&final_key_path) {
        Ok(mut key_data) => {
            let mut secret = [0u8; rusty_api::ARGON2_OUTPUT_SIZE];
            let copy_len = std::cmp::min(key_data.len(), secret.len());
            secret[..copy_len].copy_from_slice(&key_data[..copy_len]);
            key_data.zeroize();

            let file_name = std::path::Path::new(file_path)
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("file"))
                .to_string_lossy();
            let suggested_output_path = std::path::Path::new(key_dir).join(format!("{}.pqrypt", file_name));
            let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());

            let res = rusty_api::api::encrypt_file_pqrypt(file_path, &output_path, &secret);
            secret.zeroize();

            match res {
                Ok(_) => {
                    let full_output_path = std::path::Path::new(&output_path)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                    SecureShareResult::success(
                        "File encrypted successfully! Send this .pqrypt file to receiver.",
                        Some(full_output_path.to_string_lossy().to_string()),
                    )
                }
                Err(e) => SecureShareResult::error(&format!("Encryption error: {e}")),
            }
        }
        Err(e) => SecureShareResult::error(&format!("Error reading final.key: {e}")),
    }
}

#[inline(always)]
pub fn decrypt_file(file_path: &str, mode: &str) -> SecureShareResult {
    decrypt_file_with_key_dir(file_path, mode, ".")
}

pub fn decrypt_file_with_key_dir(file_path: &str, mode: &str, key_dir: &str) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No .pqrypt file selected");
    }

    let final_key_path = std::path::Path::new(key_dir).join("final.key");
    match fs::read(&final_key_path) {
        Ok(mut key_data) => {
            let mut secret = [0u8; rusty_api::ARGON2_OUTPUT_SIZE];
            let copy_len = std::cmp::min(key_data.len(), secret.len());
            secret[..copy_len].copy_from_slice(&key_data[..copy_len]);
            key_data.zeroize();

            let original_name = if file_path.ends_with(".pqrypt") {
                std::path::Path::new(file_path)
                    .file_name()
                    .unwrap_or(std::ffi::OsStr::new("file"))
                    .to_string_lossy()
                    .trim_end_matches(".pqrypt")
                    .to_string()
            } else {
                format!(
                    "{}.decrypted",
                    std::path::Path::new(file_path)
                        .file_name()
                        .unwrap_or(std::ffi::OsStr::new("file"))
                        .to_string_lossy()
                )
            };

            let suggested_output_path = std::path::Path::new(key_dir).join(&original_name);
            let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());

            let res = rusty_api::api::decrypt_file_pqrypt(file_path, &output_path, &secret);
            secret.zeroize();

            match res {
                Ok(_) => {
                    let full_output_path = std::path::Path::new(&output_path)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));

                    if mode == "text" {
                        match fs::read_to_string(&output_path) {
                            Ok(text_content) => {
                                let _ = fs::remove_file(&output_path);
                                SecureShareResult::success("Text message decrypted successfully!", Some(text_content))
                            }
                            Err(e) => SecureShareResult::error(&format!("Error reading decrypted text: {e}")),
                        }
                    } else {
                        SecureShareResult::success(
                            "File decrypted successfully!",
                            Some(full_output_path.to_string_lossy().to_string()),
                        )
                    }
                }
                Err(e) => SecureShareResult::error(&format!(
                    "Decryption failed: {e}. This may be due to file corruption, tampering, or wrong key selection."
                )),
            }
        }
        Err(e) => SecureShareResult::error(&format!("Error reading final.key: {e}")),
    }
}

#[inline(always)]
fn generate_unique_filename(base_path: &str) -> String {
    let path = std::path::Path::new(base_path);

    if !path.exists() {
        return base_path.to_string();
    }

    let parent = path.parent().unwrap_or(std::path::Path::new(""));
    let stem = path.file_stem().unwrap_or(std::ffi::OsStr::new("file")).to_string_lossy();
    let extension = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    for i in 1..=100 {
        let copy_suffix = "_copy".repeat(i);
        let new_filename = format!("{}{}{}", stem, copy_suffix, extension);
        let new_path = parent.join(&new_filename);

        if !new_path.exists() {
            return new_path.to_string_lossy().to_string();
        }
    }

    base_path.to_string()
}

fn auto_decrypt_pqrypt_files(key_dir: &str, mode: &str) -> Result<String, String> {
    let dir_path = std::path::Path::new(key_dir);
    let entries = fs::read_dir(dir_path).map_err(|e| format!("Cannot read directory: {e}"))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pqrypt") {
            let file_path = path.to_string_lossy().to_string();
            let result = decrypt_file_with_key_dir(&file_path, mode, key_dir);
            if result.success {
                if let Some(content) = result.file_path {
                    return Ok(content);
                }
            }
        }
    }

    Err("No .pqrypt files found to decrypt".to_string())
}
