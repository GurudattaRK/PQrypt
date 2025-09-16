use slint::ComponentHandle;
use rfd::FileDialog;
use std::path::PathBuf;
use std::fs;
use std::io::{self, Write};
use std::time::Instant;

use rust_ui::rusty_api;
// Import your Slint UI
slint::include_modules!();

// State management for PQC key exchange

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

// Helper function to hash password/key file data to 128 bytes (Android-compatible: saltless, mobile params)
fn hash_password_or_keyfile(data: &[u8]) -> Result<[u8; 128], rusty_api::CryptoError> {
    let empty_salt: [u8; 0] = [];
    let hash_vec = rust_ui::rusty_api::api::argon2_hash_mobile_compat(data, &empty_salt, 128)?;
    let mut result = [0u8; 128];
    result.copy_from_slice(&hash_vec);
    Ok(result)
}

// Performance test function
fn run_performance_test() -> Result<(), Box<dyn std::error::Error>> {
    println!("Triple Encryption Performance Test");
    println!("==================================");
    
    // Read test.jpg file
    let test_data = fs::read("test.jpg")?;
    println!("Loaded test.jpg: {} bytes", test_data.len());
    
    // Generate a test master key
    let mut master_key = [0u8; 128];
    rusty_api::utils::secure_random_bytes(&mut master_key)?;
    
    // Test encryption
    println!("\nStarting encryption...");
    let encrypt_start = Instant::now();
    let encrypted_data = rusty_api::api::triple_encrypt(&master_key, &test_data)?;
    let encrypt_time = encrypt_start.elapsed();
    
    println!("Encryption completed in: {:.2?}", encrypt_time);
    println!("Encrypted size: {} bytes", encrypted_data.len());
    
    // Test decryption
    println!("\nStarting decryption...");
    let decrypt_start = Instant::now();
    let decrypted_data = rusty_api::api::triple_decrypt(&master_key, &encrypted_data)?;
    let decrypt_time = decrypt_start.elapsed();
    
    println!("Decryption completed in: {:.2?}", decrypt_time);
    
    // Verify data integrity
    let original_len = test_data.len();
    let decrypted_trimmed = &decrypted_data[..original_len];
    
    if decrypted_trimmed == test_data {
        println!("✅ Data integrity verified!");
    } else {
        println!("❌ Data integrity check failed!");
        return Err("Data integrity check failed".into());
    }
    
    // Performance summary
    println!("\n=== PERFORMANCE SUMMARY ===");
    println!("File size: {} bytes", test_data.len());
    println!("Encryption time: {:.2?}", encrypt_time);
    println!("Decryption time: {:.2?}", decrypt_time);
    println!("Total time: {:.2?}", encrypt_time + decrypt_time);
    println!("Encryption speed: {:.2} MB/s", 
             (test_data.len() as f64 / 1_000_000.0) / encrypt_time.as_secs_f64());
    println!("Decryption speed: {:.2} MB/s", 
             (test_data.len() as f64 / 1_000_000.0) / decrypt_time.as_secs_f64());
    
    Ok(())
}

fn main() -> Result<(), slint::PlatformError> {
    // Check for performance test argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "test" {
        if let Err(e) = run_performance_test() {
            eprintln!("Performance test failed: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }
    
    let ui = MainWindow::new()?;
    let ui_handle = ui.as_weak();

    // Exit app callback (Welcome screen)
    {
        let ui_weak = ui_handle.clone();
        ui.on_exit_app(move || {
            let _ = ui_weak.unwrap();
            std::process::exit(0);
        });
    }
    
    // File Encryption Callbacks
    
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
    
    // Select key file callback
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
    
    // Encrypt file callback
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

        // Derive master key (Argon2 saltless, same as Android)
        let master_key = if !key_file_path.is_empty() {
            match fs::read(&key_file_path) {
                Ok(key_data) => match hash_password_or_keyfile(&key_data) {
                    Ok(key) => key,
                    Err(e) => {
                        ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                        return;
                    }
                },
                Err(e) => {
                    ui.set_output_file_path(std::format!("Error reading key file: {}", e).into());
                    return;
                }
            }
        } else if !password.is_empty() {
            match hash_password_or_keyfile(password.as_bytes()) {
                Ok(key) => key,
                Err(e) => {
                    ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                    return;
                }
            }
        } else {
            ui.set_output_file_path("No password or key file found".into());
            return;
        };

        // Read the file to encrypt
        let file_data = match fs::read(&file_path) {
            Ok(data) => data,
            Err(e) => {
                ui.set_output_file_path(std::format!("Error reading file: {}", e).into());
                return;
            }
        };

        // Encrypt the data (returns IV||ciphertext||TAG)
        let blob = match rusty_api::api::triple_encrypt(&master_key, &file_data) {
            Ok(data) => data,
            Err(e) => {
                ui.set_output_file_path(std::format!("Encryption error: {}", e).into());
                return;
            }
        };

        // Build PQRYPT header
        let total_length = file_data.len();
        let iv_size = rusty_api::AES256_IV_SIZE as usize;
        let tag_size = rusty_api::AES256_TAG_SIZE as usize;
        let ciphertext_len = if blob.len() >= iv_size + tag_size { blob.len() - iv_size - tag_size } else { 0 };
        let chunk_count = if ciphertext_len == 0 { 0 } else { ciphertext_len / 128 };

        let mut out = Vec::with_capacity(32 + blob.len());
        out.extend_from_slice(b"PQRYPT\n");
        out.extend_from_slice(total_length.to_string().as_bytes());
        out.extend_from_slice(b"\n");
        out.extend_from_slice(chunk_count.to_string().as_bytes());
        out.extend_from_slice(b"\n");
        out.extend_from_slice(&blob);

        // Write header+blob to output file
        let output_path = std::format!("{}.encrypted", file_path);
        match fs::write(&output_path, out) {
            Ok(_) => {
                let full_output_path = std::path::Path::new(&output_path)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
            }
            Err(e) => {
                ui.set_output_file_path(std::format!("Error writing encrypted file: {}", e).into());
            }
        }
    });

    // Decrypt file callback
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

        // Derive master key
        let master_key = if !key_file_path.is_empty() {
            match fs::read(&key_file_path) {
                Ok(key_data) => match hash_password_or_keyfile(&key_data) {
                    Ok(key) => key,
                    Err(e) => {
                        ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                        return;
                    }
                },
                Err(e) => {
                    ui.set_output_file_path(std::format!("Error reading key file: {}", e).into());
                    return;
                }
            }
        } else if !password.is_empty() {
            match hash_password_or_keyfile(password.as_bytes()) {
                Ok(key) => key,
                Err(e) => {
                    ui.set_output_file_path(std::format!("Key derivation error: {}", e).into());
                    return;
                }
            }
        } else {
            ui.set_output_file_path("No password or key file found".into());
            return;
        };

        // Read the file to decrypt
        let file_data = match fs::read(&file_path) {
            Ok(data) => data,
            Err(e) => {
                ui.set_output_file_path(std::format!("Error reading file: {}", e).into());
                return;
            }
        };

        // Parse PQRYPT header if present; else treat entire file as raw blob
        let (original_len, blob_start) = match parse_pqrypt_header(&file_data) {
            Ok((len, start)) => (len, start),
            Err(_) => (0usize, 0usize), // No header; raw
        };
        let blob = &file_data[blob_start..];

        // Decrypt the data
        match rusty_api::api::triple_decrypt(&master_key, blob) {
            Ok(decrypted_data) => {
                // Trim to original length if header present and plausible
                let final_data = if original_len > 0 && original_len <= decrypted_data.len() {
                    decrypted_data[..original_len].to_vec()
                } else {
                    decrypted_data
                };

                let output_path = if file_path.ends_with(".encrypted") {
                    file_path.trim_end_matches(".encrypted").to_string()
                } else {
                    std::format!("{}.decrypted", file_path)
                };

                match fs::write(&output_path, final_data) {
                    Ok(_) => {
                        let full_output_path = std::path::Path::new(&output_path)
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                        ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
                    }
                    Err(e) => {
                        ui.set_output_file_path(std::format!("Error writing decrypted file: {}", e).into());
                    }
                }
            }
            Err(e) => {
                ui.set_output_file_path(std::format!("Decryption failed: {}", e).into());
            }
        }
    });

    
    // PQC Key Exchange Callbacks
    
    // Open key file callback
    // --- UI Callbacks ---
    let ui_weak = ui_handle.clone();
    ui.on_open_key_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_key_file_path(full_path.to_string_lossy().to_string().into());
            // Update guidance depending on role and step
            if ui.get_sender() {
                // Sender should open 2.key at step 1 (after receiver generated it)
                // Guide to next action
                // Note: sender's step 1 means they already generated 1.key; now waiting for 2.key
                ui.set_status_text("Sender - Step 3: Open 2.key, then Generate 3.key and send 3.key to Receiver.".into());
            } else {
                // Receiver opens 1.key first
                ui.set_status_text("Receiver - Step 2: Open 1.key, then Generate 2.key and send 2.key to Sender.".into());
            }
        }
    });

    // Generate key file callback
    let ui_weak = ui_handle.clone();
    let pqc_state_ref = std::cell::RefCell::new(PqcState::new());
    ui.on_generate_key_file(move || {
        let ui = ui_weak.unwrap();
        let is_sender = ui.get_sender();
        let key_file_path = ui.get_key_file_path().to_string();
        let mut pqc_state = pqc_state_ref.borrow_mut();

        if is_sender {
            // --- Sender logic ---
            if pqc_state.step == 0 {
                // Step 1: Sender init
                // let (sender_bundle, sender_state) = crypto_layered_hybrid_sender_init();
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
                // Step 3: Sender processes receiver's response
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
                // Step 5: Sender writes final shared secret
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
            // --- Receiver logic ---
            if pqc_state.step == 0 && !key_file_path.is_empty() {
                // Step 2: Receiver processes sender's initial bundle (1.key) -> produce 2.key
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
                // Step 4: Receiver finalizes exchange by opening 3.key -> produce final.key
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
    
    // Password Generator Callback
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
        
        // Derive password hash using Android-compatible flow
        let first_hash = match rust_ui::rusty_api::api::derive_password_hash_android_compat(&app_name, &app_password, &master_password) {
            Ok(hash) => hash,
            Err(_) => return,
        };
        // Step 2: If app password exists, hash the first hash with app password as salt
        // let final_hash = if !app_password.is_empty() {
        //     crypto_argon2id_hash(&first_hash, app_password.as_bytes(), 64)
        // } else {
        //     first_hash
        // };
        
        // Configure character sets: first 3 are compulsory, last 3 are optional
        let mut enabled_symbol_sets = [false; 3];
        enabled_symbol_sets[0] = set1_enabled;  // This maps to symbol set 4 in the API
        enabled_symbol_sets[1] = set2_enabled;  // This maps to symbol set 5 in the API  
        enabled_symbol_sets[2] = set3_enabled;  // This maps to symbol set 6 in the API
        
        // Generate password using BASE93 mode (mode = 0) to match Android
        // The API enforces that first 3 sets are always enabled in charset mode; not used in BASE93
        if let Ok(password) = rusty_api::generate_password_secure(0, &first_hash, length, &enabled_symbol_sets, "default_user") {
            
            // Display the password in the UI only - no file storage
            ui.set_generated_password(password.into());
        } else {
            println!("Failed to generate password");
            ui.set_generated_password("Failed to generate password".into());
        }
    });
    
    ui.run()
}

// Parse PQRYPT header; returns (original_length, blob_start_offset)
fn parse_pqrypt_header(bytes: &[u8]) -> Result<(usize, usize), ()> {
    // Helper to read a line ending at '\n'
    fn read_line(data: &[u8], mut idx: usize) -> Option<(String, usize)> {
        let mut end = idx;
        while end < data.len() && data[end] != b'\n' { end += 1; }
        if end > data.len() { return None; }
        let s = String::from_utf8_lossy(&data[idx..end]).to_string();
        let next = if end < data.len() { end + 1 } else { end };
        Some((s, next))
    }

    let mut idx = 0usize;
    let (first, i1) = read_line(bytes, idx).ok_or(())?;
    if first != "PQRYPT" { return Err(()); }
    let (len_line, i2) = read_line(bytes, i1).ok_or(())?;
    let (chunks_line, i3) = read_line(bytes, i2).ok_or(())?;
    // Validate
    let original_len: usize = len_line.parse().map_err(|_| ())?;
    let _num_chunks: usize = chunks_line.parse().map_err(|_| ())?;
    // The next byte is the start of the binary blob
    Ok((original_len, i3))
}
