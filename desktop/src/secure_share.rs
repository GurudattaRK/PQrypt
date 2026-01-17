use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

use crate::rusty_api;

pub struct SecureShareState {
    pub pqc_state: PqcState,
    pub temp_text_file: Option<String>,
    pub is_sender: bool,
    pub mode: String,
    pub step: u8,
    pub key_output_dir: String,
    final_key: Option<[u8; rusty_api::ARGON2_OUTPUT_SIZE]>,
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
            final_key: None,
        }
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.pqc_state = PqcState::new();
        if let Some(temp_file) = &self.temp_text_file {
            let _ = fs::remove_file(temp_file);
        }
        self.temp_text_file = None;
        if let Some(mut k) = self.final_key.take() {
            k.zeroize();
        }
        self.is_sender = false;
        self.mode = "file".to_string();
        self.step = 0;
    }

    #[inline(always)]
    pub fn reset_flow(&mut self, mode: &str) {
        let dir = self.key_output_dir.clone();
        self.reset();
        self.key_output_dir = dir;
        self.mode = mode.to_string();
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
    pub key_path: Option<String>,
    pub out_path: Option<String>,
    pub text: Option<String>,
}

impl SecureShareResult {
    #[inline(always)]
    pub fn success(message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            key_path: None,
            out_path: None,
            text: None,
        }
    }

    #[inline(always)]
    pub fn key(message: &str, key_path: String) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            key_path: Some(key_path),
            out_path: None,
            text: None,
        }
    }

    #[inline(always)]
    pub fn out(message: &str, out_path: String) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            key_path: None,
            out_path: Some(out_path),
            text: None,
        }
    }

    #[inline(always)]
    pub fn key_out(message: &str, key_path: String, out_path: String) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            key_path: Some(key_path),
            out_path: Some(out_path),
            text: None,
        }
    }

    #[inline(always)]
    pub fn text(message: &str, text: String) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            key_path: None,
            out_path: None,
            text: Some(text),
        }
    }

    #[inline(always)]
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            key_path: None,
            out_path: None,
            text: None,
        }
    }
}

#[inline(always)]
pub fn start_sender(state: &mut SecureShareState, text_content: Option<&str>, file_path: Option<&str>) -> SecureShareResult {
    state.pqc_state = PqcState::new();
    if let Some(temp_file) = &state.temp_text_file {
        let _ = fs::remove_file(temp_file);
    }
    state.temp_text_file = None;
    if let Some(mut k) = state.final_key.take() {
        k.zeroize();
    }

    state.is_sender = true;

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
            state.step = 1;
            let full_path = key_path.canonicalize().unwrap_or_else(|_| key_path.clone());
            SecureShareResult::key(
                "Step 1: 1.key generated! Send this file to the receiver and wait for their response",
                format!("{} - Send this to Receiver", full_path.to_string_lossy()),
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

    if state.mode == "text" {
        SecureShareResult::success(
            "Step 1: Wait for sender's 1.key. Once received, press 'Open 1.key' to generate 2.key. Then wait for the encrypted .pqrypt file.",
        )
    } else {
        SecureShareResult::success(
            "Step 1: Wait for sender's 1.key. Once received, press 'Open 1.key' to generate 2.key.",
        )
    }
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

        if state.mode == "text" {
            let final_key = match rusty_api::hybrid::hybrid_sender_final(&receiver_bundle, sender_state) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
            };

            state.final_key = Some(final_key);
            state.pqc_state.step = 2;
            state.step = 2;

            let Some(temp_file) = state.temp_text_file.as_deref() else {
                return SecureShareResult::error("No text file to encrypt");
            };
            let secret = state.final_key.as_ref().unwrap();

            let enc = encrypt_file_with_secret(temp_file, &state.key_output_dir, secret);
            if enc.success {
                SecureShareResult::out(
                    "Final key generated and message encrypted. Send the encrypted .pqrypt file to receiver.",
                    enc.out_path.unwrap_or_default(),
                )
            } else {
                enc
            }
        } else {
            let Some(file_to_encrypt) = file_path else {
                return SecureShareResult::error("Please select a file to encrypt");
            };
            if file_to_encrypt.is_empty() {
                return SecureShareResult::error("Please select a file to encrypt");
            }

            let (pkg3, final_key) = match rusty_api::hybrid::hybrid_sender_third(&receiver_bundle, sender_state) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
            };

            state.final_key = Some(final_key);
            state.pqc_state.step = 2;
            state.step = 3;

            let secret = state.final_key.as_ref().unwrap();
            let enc = encrypt_file_with_secret(file_to_encrypt, &state.key_output_dir, secret);
            if enc.success {
                let Some(out_path) = enc.out_path else {
                    return SecureShareResult::error("Encryption succeeded but output file path is missing");
                };

                let tmp_base = std::path::Path::new(&state.key_output_dir).join("pqrypt_combined.pqrypt");
                let tmp_path = generate_unique_filename(&tmp_base.to_string_lossy());

                let mut input = match File::open(&out_path) {
                    Ok(v) => v,
                    Err(e) => return SecureShareResult::error(&format!("Error opening encrypted file: {e}")),
                };
                let mut out = match File::create(&tmp_path) {
                    Ok(v) => v,
                    Err(e) => return SecureShareResult::error(&format!("Error creating combined file: {e}")),
                };

                if let Err(e) = out.write_all(&pkg3) {
                    let _ = fs::remove_file(&tmp_path);
                    return SecureShareResult::error(&format!("Error writing embedded 3.key: {e}"));
                }

                let mut buf = [0u8; 131072];
                loop {
                    let n = match input.read(&mut buf) {
                        Ok(0) => break,
                        Ok(v) => v,
                        Err(e) => {
                            let _ = fs::remove_file(&tmp_path);
                            return SecureShareResult::error(&format!("Error reading encrypted file: {e}"));
                        }
                    };
                    if let Err(e) = out.write_all(&buf[..n]) {
                        let _ = fs::remove_file(&tmp_path);
                        return SecureShareResult::error(&format!("Error writing combined file: {e}"));
                    }
                }

                let _ = out.flush();

                if let Err(e) = fs::remove_file(&out_path) {
                    let _ = fs::remove_file(&tmp_path);
                    return SecureShareResult::error(&format!("Error replacing encrypted file: {e}"));
                }
                if let Err(e) = fs::rename(&tmp_path, &out_path) {
                    let _ = fs::remove_file(&tmp_path);
                    return SecureShareResult::error(&format!("Error replacing encrypted file: {e}"));
                }

                SecureShareResult::out(
                    "3.key embedded into the encrypted file. Send the encrypted .pqrypt file to receiver.",
                    out_path,
                )
            } else {
                enc
            }
        }
    } else {
        if state.mode == "text" {
            if state.pqc_state.step != 0 {
                return SecureShareResult::error("Invalid step for receiver key generation");
            }

            let sender_pkg1 = match fs::read(key_file_path) {
                Ok(b) => b,
                Err(e) => return SecureShareResult::error(&format!("Error reading key: {e}")),
            };

            let (pkg2, final_key) = match rusty_api::hybrid::hybrid_receiver(&sender_pkg1) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Key exchange error: {e}")),
            };

            state.final_key = Some(final_key);
            state.pqc_state.step = 2;
            state.step = 2;

            let key2_path = std::path::Path::new(&state.key_output_dir).join("2.key");
            match fs::write(&key2_path, &pkg2) {
                Ok(_) => {
                    let full_path = key2_path.canonicalize().unwrap_or_else(|_| key2_path.clone());
                    SecureShareResult::key(
                        "Step 2: 2.key generated. Send it to sender and wait for the encrypted message file.",
                        format!("{} - Send this to Sender", full_path.to_string_lossy()),
                    )
                }
                Err(e) => SecureShareResult::error(&format!("Error saving key: {e}")),
            }
        } else if state.pqc_state.step == 0 {
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
                    SecureShareResult::key(
                        "Step 2: 2.key generated. Send it to sender and wait for the encrypted .pqrypt file.",
                        format!("{} - Send this to Sender", full_path.to_string_lossy()),
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

            let final_key = match rusty_api::hybrid::hybrid_receiver_final_dual(&pkg3, receiver_state) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Finalize error: {e}")),
            };

            state.pqc_state.step = 2;
            state.step = 3;

            state.final_key = Some(final_key);
            SecureShareResult::success("Step 3: Final key ready. Now choose the encrypted file to decrypt.")
        } else {
            SecureShareResult::error("Invalid step for receiver key generation")
        }
    }
}

pub fn decrypt_selected(state: &mut SecureShareState, file_path: &str) -> SecureShareResult {
    if state.mode == "file" {
        let p3_len = rusty_api::PACKAGE2_SIZE;
        let file_len = match fs::metadata(file_path) {
            Ok(m) => m.len(),
            Err(e) => return SecureShareResult::error(&format!("Error reading file metadata: {e}")),
        };

        let mut f = match File::open(file_path) {
            Ok(v) => v,
            Err(e) => return SecureShareResult::error(&format!("Error opening file: {e}")),
        };

        let mut magic0 = [0u8; 6];
        if let Err(e) = f.read_exact(&mut magic0) {
            return SecureShareResult::error(&format!("Error reading file: {e}"));
        }

        let is_plain_pqrypt = &magic0 == b"PQRYPT";
        if !is_plain_pqrypt {
            if (file_len as usize) < p3_len + 73 {
                return SecureShareResult::error("Invalid encrypted file (too small for combined)");
            }

            if let Err(e) = f.seek(SeekFrom::Start(p3_len as u64)) {
                return SecureShareResult::error(&format!("Error reading file: {e}"));
            }

            let mut magic1 = [0u8; 6];
            if let Err(e) = f.read_exact(&mut magic1) {
                return SecureShareResult::error(&format!("Error reading file: {e}"));
            }

            let is_combined = &magic1 == b"PQRYPT";
            if !is_combined {
                return SecureShareResult::error("Invalid encrypted file format");
            }

            if state.final_key.is_none() {
                if state.pqc_state.step != 1 {
                    return SecureShareResult::error("No final key available. Complete the key exchange first.");
                }

                let receiver_state = match state.pqc_state.receiver_state.take() {
                    Some(s) => s,
                    None => {
                        return SecureShareResult::error(
                            "Receiver state missing. Open 1.key first to generate 2.key before decrypting.",
                        )
                    }
                };

                if let Err(e) = f.seek(SeekFrom::Start(0)) {
                    return SecureShareResult::error(&format!("Error reading file: {e}"));
                }

                let mut p3 = vec![0u8; p3_len];
                if let Err(e) = f.read_exact(&mut p3) {
                    return SecureShareResult::error(&format!("Failed to read embedded 3.key: {e}"));
                }

                let final_key = match rusty_api::hybrid::hybrid_receiver_final_dual(&p3, receiver_state) {
                    Ok(v) => v,
                    Err(e) => return SecureShareResult::error(&format!("Finalize error: {e}")),
                };

                state.final_key = Some(final_key);
                state.pqc_state.step = 2;
                state.step = 3;
            }

            let Some(secret) = state.final_key.as_ref() else {
                return SecureShareResult::error("No final key available. Complete the key exchange first.");
            };

            let base_tmp = std::path::Path::new(&state.key_output_dir).join("pqrypt_trimmed.pqrypt");
            let tmp_path = generate_unique_filename(&base_tmp.to_string_lossy());

            let mut input = match File::open(file_path) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Error opening file: {e}")),
            };

            if let Err(e) = input.seek(SeekFrom::Start(p3_len as u64)) {
                return SecureShareResult::error(&format!("Error reading encrypted file: {e}"));
            }

            let mut out = match File::create(&tmp_path) {
                Ok(v) => v,
                Err(e) => return SecureShareResult::error(&format!("Error creating temp file: {e}")),
            };

            let mut buf = [0u8; 131072];
            loop {
                let n = match input.read(&mut buf) {
                    Ok(0) => break,
                    Ok(v) => v,
                    Err(e) => return SecureShareResult::error(&format!("Error reading encrypted file: {e}")),
                };
                if let Err(e) = out.write_all(&buf[..n]) {
                    return SecureShareResult::error(&format!("Error writing temp file: {e}"));
                }
            }

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

            let suggested_output_path = std::path::Path::new(&state.key_output_dir).join(&original_name);
            let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());

            let res = match rusty_api::api::decrypt_file_pqrypt(&tmp_path, &output_path, secret) {
                Ok(_) => {
                    let full_output_path = std::path::Path::new(&output_path)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));

                    if state.mode == "text" {
                        match fs::read_to_string(&output_path) {
                            Ok(text_content) => {
                                let _ = fs::remove_file(&output_path);
                                SecureShareResult::text("Text message decrypted successfully!", text_content)
                            }
                            Err(e) => SecureShareResult::error(&format!("Error reading decrypted text: {e}")),
                        }
                    } else {
                        SecureShareResult::out(
                            "File decrypted successfully!",
                            full_output_path.to_string_lossy().to_string(),
                        )
                    }
                }
                Err(e) => SecureShareResult::error(&format!(
                    "Decryption failed: {e}. This may be due to file corruption, tampering, or wrong key selection."
                )),
            };
            let _ = fs::remove_file(&tmp_path);

            if res.success {
                return res;
            }

            return res;
        }
    }

    let Some(secret) = state.final_key.as_ref() else {
        return SecureShareResult::error("No final key available. Complete the key exchange first.");
    };
    decrypt_file_with_secret(file_path, &state.mode, &state.key_output_dir, secret)
}

pub fn encrypt_selected(state: &SecureShareState, file_path: &str) -> SecureShareResult {
    let Some(secret) = state.final_key.as_ref() else {
        return SecureShareResult::error("No final key available. Complete the key exchange first.");
    };
    encrypt_file_with_secret(file_path, &state.key_output_dir, secret)
}

fn encrypt_file_with_secret(
    file_path: &str,
    key_dir: &str,
    secret: &[u8; rusty_api::ARGON2_OUTPUT_SIZE],
) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No file to encrypt");
    }

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .unwrap_or(std::ffi::OsStr::new("file"))
        .to_string_lossy();
    let suggested_output_path = std::path::Path::new(key_dir).join(format!("{}.pqrypt", file_name));
    let output_path = generate_unique_filename(&suggested_output_path.to_string_lossy());

    let res = rusty_api::api::encrypt_file_pqrypt(file_path, &output_path, secret);
    match res {
        Ok(_) => {
            let full_output_path = std::path::Path::new(&output_path)
                .canonicalize()
                .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
            SecureShareResult::out("File encrypted successfully!", full_output_path.to_string_lossy().to_string())
        }
        Err(e) => SecureShareResult::error(&format!("Encryption error: {e}")),
    }
}

fn decrypt_file_with_secret(
    file_path: &str,
    mode: &str,
    key_dir: &str,
    secret: &[u8; rusty_api::ARGON2_OUTPUT_SIZE],
) -> SecureShareResult {
    if file_path.is_empty() {
        return SecureShareResult::error("No .pqrypt file selected");
    }

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

    let res = rusty_api::api::decrypt_file_pqrypt(file_path, &output_path, secret);
    match res {
        Ok(_) => {
            let full_output_path = std::path::Path::new(&output_path)
                .canonicalize()
                .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));

            if mode == "text" {
                match fs::read_to_string(&output_path) {
                    Ok(text_content) => {
                        let _ = fs::remove_file(&output_path);
                        SecureShareResult::text("Text message decrypted successfully!", text_content)
                    }
                    Err(e) => SecureShareResult::error(&format!("Error reading decrypted text: {e}")),
                }
            } else {
                SecureShareResult::out("File decrypted successfully!", full_output_path.to_string_lossy().to_string())
            }
        }
        Err(e) => SecureShareResult::error(&format!(
            "Decryption failed: {e}. This may be due to file corruption, tampering, or wrong key selection."
        )),
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
