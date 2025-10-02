use slint::ComponentHandle;
use rfd::FileDialog;
use std::path::Path;
use std::fs;
use std::rc::Rc;

use pqrypt::rusty_api;
use pqrypt::secure_share;
// Import your Slint UI
slint::include_modules!();

struct PqcState {
    sender_state: Option<rusty_api::hybrid::HybridSenderState>,
    receiver_state: Option<rusty_api::hybrid::HybridReceiverState>,
    final_shared_secret: Option<[u8; 128]>, // final 128-byte secret
    step: u8,
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


// MARK: hash_password_or_keyfile
fn hash_password_or_keyfile(data: &[u8]) -> Result<[u8; 256], rusty_api::CryptoError> {
    let empty_salt: [u8; 0] = [];
    let hash_vec = pqrypt::rusty_api::api::argon2_hash_mobile_compat(data, &empty_salt, 256)?;
    let mut result = [0u8; 256];
    result.copy_from_slice(&hash_vec);
    Ok(result)
}

// MARK: generate_unique_filename
fn generate_unique_filename(base_path: &str) -> String {
    let path = Path::new(base_path);
    
    if !path.exists() {
        return base_path.to_string();
    }
    
    // Extract filename and extension
    let parent = path.parent().unwrap_or(Path::new(""));
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


fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    let ui_handle = ui.as_weak();

    {
        let ui_weak = ui_handle.clone();
        ui.on_exit_app(move || {
            let _ = ui_weak.unwrap();
            std::process::exit(0);
        });
    }
    
    // Choose file callback
    let ui_weak = ui_handle.clone();
    ui.on_choose_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new()
            .pick_file()
        {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_file_path(full_path.to_string_lossy().to_string().into());
        }
    });
    
    let ui_weak = ui_handle.clone();
    ui.on_select_key_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new()
            .pick_file()
        {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_key_file_path(full_path.to_string_lossy().to_string().into());
        }
    });
    
    let ui_weak = ui_handle.clone();
    ui.on_encrypt_file(move || {
        let ui = ui_weak.unwrap();
        let file_path = ui.get_file_path().to_string();
        let password = ui.get_password().to_string();
        let key_file_path = ui.get_key_file_path().to_string();

        if file_path.is_empty() {
            ui.set_output_file_path("Please select a file first".into());
            return;
        }

        // Derive secret key from password or key file (match Android exactly)
        let secret = if !key_file_path.is_empty() {
            match fs::read(&key_file_path) {
                Ok(key_data) => {
                    // Use first 128 bytes for key file mode to match Android
                    if key_data.len() > 128 { key_data[..128].to_vec() } else { key_data }
                },
                Err(e) => {
                    ui.set_output_file_path(std::format!("Error reading key file: {}", e).into());
                    return;
                }
            }
        } else if !password.is_empty() {
            // Derive 128-byte key from password using Argon2 (match Android key derivation)
            match hash_password_or_keyfile(password.as_bytes()) {
                Ok(key) => key.to_vec(),
                Err(e) => {
                    ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                    return;
                }
            }
        } else {
            ui.set_output_file_path("No password or key file found".into());
            return;
        };

        let suggested_output_path = std::format!("{}.pqrypt2", file_path);
        let output_path = generate_unique_filename(&suggested_output_path);
        match rusty_api::api::encrypt_file_pqrypt2(&file_path, &output_path, &secret) {
            Ok(_) => {
                let full_output_path = std::path::Path::new(&output_path)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
            }
            Err(e) => {
                ui.set_output_file_path(std::format!("Encryption error: {}", e).into());
            }
        }
    });

    let ui_weak = ui_handle.clone();
    ui.on_decrypt_file(move || {
        let ui = ui_weak.unwrap();
        let file_path = ui.get_file_path().to_string();
        let password = ui.get_password().to_string();
        let key_file_path = ui.get_key_file_path().to_string();

        if file_path.is_empty() {
            ui.set_output_file_path("Please select a file first".into());
            return;
        }

        // Derive secret key from password or key file (match Android exactly)
        let secret = if !key_file_path.is_empty() {
            match fs::read(&key_file_path) {
                Ok(key_data) => {
                    // Use first 128 bytes for key file mode to match Android
                    if key_data.len() > 128 { key_data[..128].to_vec() } else { key_data }
                },
                Err(e) => {
                    ui.set_output_file_path(std::format!("Error reading key file: {}", e).into());
                    return;
                }
            }
        } else if !password.is_empty() {
            // Derive 128-byte key from password using Argon2 (match Android key derivation)
            match hash_password_or_keyfile(password.as_bytes()) {
                Ok(key) => key.to_vec(),
                Err(e) => {
                    ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                    return;
                }
            }
        } else {
            ui.set_output_file_path("No password or key file found".into());
            return;
        };

        let suggested_output_path = if file_path.ends_with(".pqrypt2") {
            file_path.trim_end_matches(".pqrypt2").to_string()
        } else if file_path.ends_with(".encrypted") {
            file_path.trim_end_matches(".encrypted").to_string()
        } else {
            std::format!("{}.decrypted", file_path)
        };
        
        let output_path = generate_unique_filename(&suggested_output_path);

        match rusty_api::api::decrypt_file_pqrypt2(&file_path, &output_path, &secret) {
            Ok(_) => {
                let full_output_path = std::path::Path::new(&output_path)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
            }
            Err(e) => {
                let error_msg = if e.to_string().contains("Authentication failed") || 
                                   e.to_string().contains("GCM") ||
                                   e.to_string().contains("tag") {
                    "Authentication/decryption failed. This may be due to file corruption, tampering, or wrong password.".to_string()
                } else {
                    std::format!("Decryption failed: {}. This may be due to file corruption, tampering, or wrong password.", e)
                };
                ui.set_output_file_path(error_msg.into());
            }
        }
    });

    
    // Open key file callback
    let ui_weak = ui_handle.clone();
    ui.on_open_key_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_key_file_path(full_path.to_string_lossy().to_string().into());
            if ui.get_sender() {
                ui.set_status_text("Sender - Step 3: Open 2.key, then Generate 3.key and send 3.key to Receiver.".into());
            } else {
                ui.set_status_text("Receiver - Step 2: Open 1.key, then Generate 2.key and send 2.key to Sender.".into());
            }
        }
    });

    let ui_weak = ui_handle.clone();
    let pqc_state_ref = std::cell::RefCell::new(PqcState::new());
    let secure_share_state_ref = Rc::new(std::cell::RefCell::new(secure_share::SecureShareState::new()));
    ui.on_generate_key_file(move || {
        let ui = ui_weak.unwrap();
        let is_sender = ui.get_sender();
        let key_file_path = ui.get_key_file_path().to_string();
        let mut pqc_state = pqc_state_ref.borrow_mut();

        if is_sender {
            if pqc_state.step == 0 {
                let (sender_bundle, sender_state) = match rusty_api::pqc_4hybrid_init() { 
                    Ok(result) => result, Err(e) => { 
                        ui.set_generated_key_path(std::format!("Error: {}", e).into()); return; 
                    } 
                };

                pqc_state.sender_state = Some(sender_state);
                pqc_state.step = 1;

                match fs::write("1.key", sender_bundle) {
                    Ok(_) => {
                        let full_path = std::path::Path::new("1.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("1.key"));
                        ui.set_generated_key_path(std::format!("{} - Send this to Receiver", full_path.to_string_lossy()).into());
                        ui.set_status_text("Sender - Step 1 complete. Generated 1.key. Step 2: Send 1.key to Receiver.".into());
                    }
                    Err(e) => ui.set_generated_key_path(std::format!("Error: {}", e).into()),
                }

            } else if pqc_state.step == 1 && !key_file_path.is_empty() {
                match fs::read(&key_file_path) {
                    Ok(receiver_bundle) => {
                        if let Some(sender_state) = &pqc_state.sender_state {
                            match rusty_api::pqc_4hybrid_snd_final(&receiver_bundle, sender_state) {
                                Ok((final_shared_secret, sender_final_bundle)) => {
                                    pqc_state.final_shared_secret = Some(final_shared_secret);
                                    pqc_state.step = 2;

                                    match fs::write("3.key", &sender_final_bundle) {
                                        Ok(_) => {
                                            let full_path = std::path::Path::new("3.key")
                                                .canonicalize()
                                                .unwrap_or_else(|_| std::path::PathBuf::from("3.key"));
                                            ui.set_generated_key_path(std::format!("{} - Send this to Receiver", full_path.to_string_lossy()).into());
                                            ui.set_status_text("Sender - Step 3 complete. Generated 3.key. Step 4: Send 3.key to Receiver.".into());
                                        }
                                        Err(e) => ui.set_generated_key_path(std::format!("Error: {}", e).into()),
                                    }
                                }
                                Err(e) => ui.set_generated_key_path(std::format!("Exchange error: {}", e).into()),
                            }
                        }
                    }
                    Err(e) => ui.set_generated_key_path(std::format!("Error reading 2.key: {}", e).into()),
                }

            } else if pqc_state.step == 2 {
                if let Some(final_shared_secret) = &pqc_state.final_shared_secret {
                    match fs::write("final.key", final_shared_secret) {
                        Ok(_) => {
                            let full_path = std::path::Path::new("final.key")
                                .canonicalize()
                                .unwrap_or_else(|_| std::path::PathBuf::from("final.key"));
                            ui.set_generated_key_path(std::format!("{} - Key exchange complete!", full_path.to_string_lossy()).into());
                            ui.set_status_text("Key exchange completed successfully!".into());
                        }
                        Err(e) => ui.set_generated_key_path(std::format!("Error: {}", e).into()),
                    }
                } else {
                    ui.set_generated_key_path("Error: No shared secret available".into());
                }
            }

        } else {
            if pqc_state.step == 0 && !key_file_path.is_empty() {
                match fs::read(&key_file_path) {
                    Ok(sender_bundle) => {
                        let (receiver_bundle, receiver_state) = match rusty_api::pqc_4hybrid_recv(&sender_bundle) {
                            Ok(result) => result,
                            Err(e) => { ui.set_generated_key_path(std::format!("Error: {}", e).into()); return; }
                        };
                        pqc_state.receiver_state = Some(receiver_state);
                        pqc_state.step = 1;
                        match fs::write("2.key", &receiver_bundle) {
                            Ok(_) => {
                                let full_path = std::path::Path::new("2.key")
                                    .canonicalize()
                                    .unwrap_or_else(|_| std::path::PathBuf::from("2.key"));
                                ui.set_generated_key_path(std::format!("{} - Send this to Sender", full_path.to_string_lossy()).into());
                                ui.set_status_text("Receiver - Step 2 complete. Generated 2.key. Step 3: Send 2.key to Sender.".into());
                            }
                            Err(e) => ui.set_generated_key_path(std::format!("Error: {}", e).into()),
                        }
                    }
                    Err(e) => ui.set_generated_key_path(std::format!("Error reading 1.key: {}", e).into()),
                }
            } else if pqc_state.step == 1 && !key_file_path.is_empty() {
                match fs::read(&key_file_path) {
                    Ok(sender_final_bundle) => {
                        if let Some(receiver_state) = &pqc_state.receiver_state {
                            match rusty_api::pqc_4hybrid_recv_final(&sender_final_bundle, receiver_state) {
                                Ok(final_shared_secret) => {
                                    pqc_state.step = 2;
                                    pqc_state.final_shared_secret = Some(final_shared_secret);
                                    match fs::write("final.key", &final_shared_secret) {
                                        Ok(_) => {
                                            let full_path = std::path::Path::new("final.key")
                                                .canonicalize()
                                                .unwrap_or_else(|_| std::path::PathBuf::from("final.key"));
                                            ui.set_generated_key_path(std::format!("{} - Key exchange complete!", full_path.to_string_lossy()).into());
                                            ui.set_status_text("Receiver - Step 5 complete. Key exchange completed successfully! Saved final.key.".into());
                                        }
                                        Err(e) => ui.set_generated_key_path(std::format!("Error: {}", e).into()),
                                    }
                                }
                                Err(e) => ui.set_generated_key_path(std::format!("Finalize error: {}", e).into()),
                            }
                        }
                    }
                    Err(e) => ui.set_generated_key_path(std::format!("Error reading 3.key: {}", e).into()),
                }
            }
        }
    });
    
    let ui_weak = ui_handle.clone();
    ui.on_generate_password(move || {
        let ui = ui_weak.unwrap();
        let app_name = ui.get_app_name().to_string();
        let app_password = ui.get_app_password().to_string();
        let master_password = ui.get_master_password().to_string();
        let length = ui.get_password_length() as usize;
        let set1_enabled = ui.get_set1_enabled();
        let set2_enabled = ui.get_set2_enabled();
        let set3_enabled = ui.get_set3_enabled();
        
        if master_password.is_empty() {
            return;
        }
        
        let first_hash = match pqrypt::rusty_api::api::derive_password_hash_unified_128(&app_name, &app_password, &master_password) {
            Ok(hash) => hash,
            Err(_) => return,
        };
        let mut enabled_symbol_sets = [false; 3];
        enabled_symbol_sets[0] = set1_enabled;
        enabled_symbol_sets[1] = set2_enabled;
        enabled_symbol_sets[2] = set3_enabled;
        if let Some(password) = rusty_api::generate_password(1, &first_hash, length, &enabled_symbol_sets) {
            ui.set_generated_password(password.into());
        } else {
            ui.set_generated_password("Failed to generate password".into());
        }
    });
    
    // Secure Share Choose File callback
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_choose = secure_share_state_ref.clone();
    ui.on_secure_share_choose_file(move || {
        let ui = ui_weak.unwrap();
        let secure_share_state = secure_share_state_ref_choose.borrow();
        
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            let file_path = full_path.to_string_lossy().to_string();
            ui.set_file_path(file_path.clone().into());
            
            if !secure_share_state.is_sender && secure_share_state.pqc_state.step == 2 {
                let mode = secure_share_state.mode.clone();
                let key_dir = secure_share_state.key_output_dir.clone();
                drop(secure_share_state);
                
                let result = secure_share::decrypt_file_with_key_dir(&file_path, &mode, &key_dir);
                
                ui.set_secure_share_status(result.message.into());
                if result.success {
                    if mode == "text" {
                        if let Some(text_content) = result.file_path {
                            ui.set_received_text(text_content.into());
                        }
                    } else {
                        if let Some(path) = result.file_path {
                            ui.set_output_file_path(path.into());
                        }
                    }
                }
            }
        }
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone = secure_share_state_ref.clone();
    ui.on_secure_share_start_sender(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_clone.borrow_mut();
        
        // Reset state to ensure clean start
        secure_share_state.reset();
        
        let mode = ui.get_secure_share_mode().to_string();
        secure_share_state.set_mode(&mode);
        
        let text_content = if mode == "text" {
            let text = ui.get_secure_share_text().to_string();
            if text.is_empty() { None } else { Some(text) }
        } else {
            None
        };
        
        let file_path = if mode == "file" {
            let path = ui.get_file_path().to_string();
            if path.is_empty() { None } else { Some(path) }
        } else {
            None
        };
        
        let result = secure_share::start_sender(&mut *secure_share_state, text_content.as_deref(), file_path.as_deref());
        
        ui.set_secure_share_status(result.message.into());
        if let Some(path) = result.file_path {
            ui.set_generated_key_path(path.into());
        }
        if result.success && mode == "text" {
            if let Some(temp_path) = &secure_share_state.temp_text_file {
                ui.set_file_path(temp_path.clone().into());
            }
        }
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone2 = secure_share_state_ref.clone();
    ui.on_secure_share_start_receiver(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_clone2.borrow_mut();
        
        // Reset state to ensure clean start
        secure_share_state.reset();
        
        let mode = ui.get_secure_share_mode().to_string();
        let result = secure_share::start_receiver(&mut *secure_share_state, &mode);
        
        ui.set_secure_share_status(result.message.into());
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone3 = secure_share_state_ref.clone();
    ui.on_secure_share_open_key(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_clone3.borrow_mut();
        
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            let key_file_path = full_path.to_string_lossy().to_string();
            ui.set_key_file_path(key_file_path.clone().into());
            
            if secure_share_state.is_sender {
                let file_to_encrypt = if secure_share_state.mode == "file" {
                    let file_path = ui.get_file_path().to_string();
                    if file_path.is_empty() { None } else { Some(file_path) }
                } else {
                    None
                };
                
                let result = secure_share::generate_key_with_file_path(&mut *secure_share_state, &key_file_path, file_to_encrypt.as_deref());
                ui.set_secure_share_status(result.message.into());
                if let Some(path) = result.file_path {
                    ui.set_generated_key_path(path.into());
                }
            } else {
                if secure_share_state.pqc_state.step == 0 {
                    let result = secure_share::generate_key_with_file_path(&mut *secure_share_state, &key_file_path, None);
                    ui.set_secure_share_status(result.message.into());
                    if let Some(path) = result.file_path {
                        ui.set_generated_key_path(path.into());
                    }
                } else if secure_share_state.pqc_state.step == 1 {
                    let mode = secure_share_state.mode.clone();
                    let result = secure_share::generate_key_with_file_path(&mut *secure_share_state, &key_file_path, None);
                    ui.set_secure_share_status(result.message.into());
                    if let Some(path) = result.file_path {
                        if mode == "text" {
                            ui.set_received_text(path.into());
                        } else {
                            ui.set_output_file_path(path.into());
                        }
                    }
                } else {
                    ui.set_secure_share_status("Opened key file.".into());
                }
            }
        }
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone4 = secure_share_state_ref.clone();
    ui.on_secure_share_generate_key(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_clone4.borrow_mut();
        let key_file_path = ui.get_key_file_path().to_string();
        
        let file_path = if secure_share_state.is_sender && secure_share_state.mode == "file" {
            Some(ui.get_file_path().to_string())
        } else {
            None
        };
        let result = secure_share::generate_key_with_file_path(&mut *secure_share_state, &key_file_path, file_path.as_deref());
        
        ui.set_secure_share_status(result.message.into());
        if let Some(path) = result.file_path {
            ui.set_generated_key_path(path.into());
        }
        
    });
    
    let ui_weak = ui_handle.clone();
    ui.on_secure_share_encrypt(move || {
        let ui = ui_weak.unwrap();
        let file_path = ui.get_file_path().to_string();
        
        let result = secure_share::encrypt_file(&file_path);
        
        ui.set_secure_share_status(result.message.into());
        if let Some(path) = result.file_path {
            ui.set_output_file_path(path.into());
        }
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone6 = secure_share_state_ref.clone();
    ui.on_secure_share_decrypt(move || {
        let ui = ui_weak.unwrap();
        let secure_share_state = secure_share_state_ref_clone6.borrow();
        let file_path = ui.get_file_path().to_string();
        
        let result = secure_share::decrypt_file(&file_path, &secure_share_state.mode);
        
        ui.set_secure_share_status(result.message.into());
        if result.success {
            if secure_share_state.mode == "text" {
                if let Some(text_content) = result.file_path {
                    ui.set_received_text(text_content.into());
                }
            } else {
                if let Some(path) = result.file_path {
                    ui.set_output_file_path(path.into());
                }
            }
        }
    });
    
    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_clone7 = secure_share_state_ref.clone();
    ui.on_secure_share_choose_key_folder(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_clone7.borrow_mut();
        
        if let Some(folder) = FileDialog::new().pick_folder() {
            let folder_path = folder.canonicalize().unwrap_or(folder);
            let folder_str = folder_path.to_string_lossy().to_string();
            secure_share_state.set_key_output_dir(&folder_str);
            ui.set_secure_share_status(format!("Key files location set to: {}", folder_str).into());
        }
    });
    
    ui.run()
}

