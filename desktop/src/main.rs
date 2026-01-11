use slint::ComponentHandle;
use rfd::FileDialog;
use std::path::Path;
use std::fs;
use std::rc::Rc;
use zeroize::Zeroize;

use pqrypt::rusty_api;
use pqrypt::secure_share;
slint::include_modules!();

struct PqcState {
    sender_state: Option<rusty_api::hybrid::HybridSenderState>,
    receiver_state: Option<rusty_api::hybrid::HybridReceiverState>,
    step: u8,
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

#[inline(always)]
fn generate_unique_filename(base_path: &str) -> String {
    let path = Path::new(base_path);

    if !path.exists() {
        return base_path.to_string();
    }

    let parent = path.parent().unwrap_or(Path::new(""));
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

#[inline(always)]
fn read_secret_from_ui(password: &str, key_file_path: &str) -> Result<Vec<u8>, String> {
    if !key_file_path.is_empty() {
        let mut key_data = fs::read(key_file_path).map_err(|e| format!("Error reading key file: {e}"))?;
        if key_data.len() < 8 {
            key_data.zeroize();
            return Err("Key file must have at least 8 bytes".to_string());
        }
        let secret = if key_data.len() > 64 {
            key_data[..64].to_vec()
        } else {
            key_data.clone()
        };
        key_data.zeroize();
        return Ok(secret);
    }

    if !password.is_empty() {
        return Ok(password.as_bytes().to_vec());
    }

    Err("No password or key file found".to_string())
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

    let ui_weak = ui_handle.clone();
    ui.on_choose_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_file_path(full_path.to_string_lossy().to_string().into());
        }
    });

    let ui_weak = ui_handle.clone();
    ui.on_select_key_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new().pick_file() {
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

        let mut secret = match read_secret_from_ui(&password, &key_file_path) {
            Ok(s) => s,
            Err(e) => {
                ui.set_output_file_path(e.into());
                return;
            }
        };

        let suggested_output_path = format!("{file_path}.pqrypt");
        let output_path = generate_unique_filename(&suggested_output_path);

        let res = rusty_api::api::encrypt_file_pqrypt(&file_path, &output_path, &secret);
        secret.zeroize();

        match res {
            Ok(_) => {
                let full_output_path = std::path::Path::new(&output_path)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
            }
            Err(e) => {
                ui.set_output_file_path(format!("Encryption error: {e}").into());
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

        let mut secret = match read_secret_from_ui(&password, &key_file_path) {
            Ok(s) => s,
            Err(e) => {
                ui.set_output_file_path(e.into());
                return;
            }
        };

        let suggested_output_path = if file_path.ends_with(".pqrypt") {
            file_path.trim_end_matches(".pqrypt").to_string()
        } else {
            format!("{file_path}.decrypted")
        };

        let output_path = generate_unique_filename(&suggested_output_path);

        let res = rusty_api::api::decrypt_file_pqrypt(&file_path, &output_path, &secret);
        secret.zeroize();

        match res {
            Ok(_) => {
                let full_output_path = std::path::Path::new(&output_path)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(&output_path));
                ui.set_output_file_path(full_output_path.to_string_lossy().to_string().into());
            }
            Err(e) => {
                ui.set_output_file_path(format!("Decryption failed: {e}").into());
            }
        }
    });

    let ui_weak = ui_handle.clone();
    ui.on_open_key_file(move || {
        let ui = ui_weak.unwrap();
        if let Some(path) = FileDialog::new().pick_file() {
            let full_path = path.canonicalize().unwrap_or(path);
            ui.set_key_file_path(full_path.to_string_lossy().to_string().into());
            if ui.get_sender() {
                ui.set_status_text("Step 2: Great! 2.key loaded. Now press 'Generate Key File' button to create 3.key and final.key".into());
            } else {
                ui.set_status_text("Step 1: Great! 1.key loaded. Now press 'Generate Key File' button to create 2.key".into());
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
                let (pkg1, sender_state) = match rusty_api::hybrid::hybrid_sender_init() {
                    Ok(v) => v,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Error: {e}").into());
                        return;
                    }
                };

                pqc_state.sender_state = Some(sender_state);
                pqc_state.step = 1;

                match fs::write("1.key", pkg1) {
                    Ok(_) => {
                        let full_path = std::path::Path::new("1.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("1.key"));
                        ui.set_generated_key_path(format!("✅ {}", full_path.to_string_lossy()).into());
                        ui.set_status_text("Step 1 complete! Send 1.key to receiver and wait for their 2.key. Then press 'Open Key File' to load 2.key".into());
                    }
                    Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
                }
            } else if pqc_state.step == 1 && !key_file_path.is_empty() {
                let receiver_bundle = match fs::read(&key_file_path) {
                    Ok(b) => b,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Error reading 2.key: {e}").into());
                        return;
                    }
                };

                let sender_state = match pqc_state.sender_state.take() {
                    Some(s) => s,
                    None => {
                        ui.set_generated_key_path("Error: Sender state missing".into());
                        return;
                    }
                };

                let (pkg3, mut final_key) = match rusty_api::hybrid::hybrid_sender_third(&receiver_bundle, sender_state) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Exchange error: {e}").into());
                        return;
                    }
                };

                let res3 = fs::write("3.key", &pkg3);
                let resf = fs::write("final.key", final_key.as_slice());
                final_key.zeroize();

                match (res3, resf) {
                    (Ok(_), Ok(_)) => {
                        let full_path_3 = std::path::Path::new("3.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("3.key"));
                        let full_path_f = std::path::Path::new("final.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("final.key"));
                        ui.set_generated_key_path(format!("✅ {}", full_path_3.to_string_lossy()).into());
                        ui.set_status_text(format!("✅ Success! Send 3.key to receiver. final.key saved at: {}", full_path_f.to_string_lossy()).into());
                        pqc_state.step = 2;
                    }
                    (Err(e), _) => ui.set_generated_key_path(format!("Error writing 3.key: {e}").into()),
                    (_, Err(e)) => ui.set_generated_key_path(format!("Error writing final.key: {e}").into()),
                }
            }
        } else {
            if pqc_state.step == 0 && !key_file_path.is_empty() {
                let sender_pkg1 = match fs::read(&key_file_path) {
                    Ok(b) => b,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Error reading 1.key: {e}").into());
                        return;
                    }
                };

                let (bundle2, receiver_state) = match rusty_api::hybrid::hybrid_receiver_dual(&sender_pkg1) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Error: {e}").into());
                        return;
                    }
                };

                pqc_state.receiver_state = Some(receiver_state);
                pqc_state.step = 1;

                match fs::write("2.key", &bundle2) {
                    Ok(_) => {
                        let full_path = std::path::Path::new("2.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("2.key"));
                        ui.set_generated_key_path(format!("✅ {}", full_path.to_string_lossy()).into());
                        ui.set_status_text("Step 1 complete! Send 2.key to sender and wait for their 3.key. Then press 'Open Key File' to load 3.key".into());
                    }
                    Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
                }
            } else if pqc_state.step == 1 && !key_file_path.is_empty() {
                let pkg3 = match fs::read(&key_file_path) {
                    Ok(b) => b,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Error reading 3.key: {e}").into());
                        return;
                    }
                };

                let receiver_state = match pqc_state.receiver_state.take() {
                    Some(s) => s,
                    None => {
                        ui.set_generated_key_path("Error: Receiver state missing".into());
                        return;
                    }
                };

                let mut final_key = match rusty_api::hybrid::hybrid_receiver_final_dual(&pkg3, receiver_state) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.set_generated_key_path(format!("Finalize error: {e}").into());
                        return;
                    }
                };

                let resf = fs::write("final.key", final_key.as_slice());
                final_key.zeroize();

                match resf {
                    Ok(_) => {
                        let full_path = std::path::Path::new("final.key")
                            .canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from("final.key"));
                        ui.set_generated_key_path(format!("✅ {}", full_path.to_string_lossy()).into());
                        ui.set_status_text("✅ Success! Key exchange completed. final.key has been saved".into());
                        pqc_state.step = 2;
                    }
                    Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
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

        let mut first_hash = match pqrypt::rusty_api::api::derive_password_hash_unified_64(&app_name, &app_password, &master_password) {
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

        first_hash.zeroize();
    });

     let ui_weak = ui_handle.clone();
     let secure_share_state_ref_choose = secure_share_state_ref.clone();
     ui.on_secure_share_choose_file(move || {
         let ui = ui_weak.unwrap();

         if let Some(path) = FileDialog::new().pick_file() {
             let full_path = path.canonicalize().unwrap_or(path);
             let file_path = full_path.to_string_lossy().to_string();
             ui.set_file_path(file_path.clone().into());

             let (is_sender, step, mode, key_dir) = {
                 let secure_share_state = secure_share_state_ref_choose.borrow();
                 (
                     secure_share_state.is_sender,
                     secure_share_state.step,
                     secure_share_state.mode.clone(),
                     secure_share_state.key_output_dir.clone(),
                 )
             };

             if !is_sender && step >= 2 {
                 let result = secure_share::decrypt_file_with_key_dir(&file_path, &mode, &key_dir);

                 ui.set_secure_share_status(result.message.into());
                 if result.success {
                     if mode == "text" {
                         if let Some(text_content) = result.file_path {
                             ui.set_received_text(text_content.into());
                         }
                     } else if let Some(path) = result.file_path {
                         ui.set_output_file_path(path.into());
                     }
                 }
             } else {
                 let mut secure_share_state = secure_share_state_ref_choose.borrow_mut();
                 let res = secure_share::start_sender(&mut secure_share_state, None, Some(file_path.as_str()));
                 ui.set_secure_share_status(res.message.into());
             }
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
        let mut secure_share_state = secure_share_state_ref_clone6.borrow_mut();

        let mode = secure_share_state.mode.clone();
        let result = secure_share::start_receiver(&mut secure_share_state, &mode);

        ui.set_secure_share_status(result.message.into());
        if result.success {
            if secure_share_state.mode == "text" {
                if let Some(text_content) = result.file_path {
                    ui.set_received_text(text_content.into());
                }
            } else if let Some(path) = result.file_path {
                ui.set_output_file_path(path.into());
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
            ui.set_secure_share_status(format!("Key files location set to: {folder_str}").into());
        }
    });

    ui.run()
}
