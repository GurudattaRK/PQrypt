use slint::ComponentHandle;
use rfd::FileDialog;
use std::cell::RefCell;
use std::path::Path;
use std::fs;
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

use copypasta::{ClipboardContext, ClipboardProvider};

use pqrypt::rusty_api;
use pqrypt::secure_share;
slint::include_modules!();

struct PqcState {
    sender_state: Option<rusty_api::hybrid::HybridSenderState>,
    receiver_state: Option<rusty_api::hybrid::HybridReceiverState>,
    step: u8,
}

const PQC_SENDER_STEP1: &str = "Step 1: Tap 'Start' to create 1.key";
const PQC_SENDER_STEP2: &str = "Step 2: Tap 'Open 2.key' (bundle) from receiver to generate 3.key and final.key";
const PQC_SENDER_DONE: &str = "✅ Complete! 3.key and final.key generated. Send 3.key to receiver";
const PQC_RECEIVER_STEP1: &str = "Step 1: Tap 'Open 1.key' from sender to generate 2.key";
const PQC_RECEIVER_STEP2: &str = "Step 2: Send 2.key to sender, then tap 'Open 3.key' when you receive it";
const PQC_RECEIVER_DONE: &str = "✅ Complete! final.key has been generated and saved";

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

    let pqc_state_ref = Rc::new(RefCell::new(PqcState::new()));
    let secure_share_state_ref = Rc::new(RefCell::new(secure_share::SecureShareState::new()));

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
    let pqc_state_ref_open = pqc_state_ref.clone();
    ui.on_open_key_file(move || {
        let ui = ui_weak.unwrap();
        let is_sender = ui.get_sender();
        let mut pqc_state = pqc_state_ref_open.borrow_mut();

        if pqc_state.step >= 2 {
            if is_sender {
                ui.set_status_text(PQC_SENDER_DONE.into());
            } else {
                ui.set_status_text(PQC_RECEIVER_DONE.into());
            }
            ui.set_pqc_action_text("Open Key File".into());
            return;
        }

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
                        ui.set_status_text(PQC_SENDER_STEP2.into());
                        ui.set_pqc_action_text("Open 2.key".into());
                    }
                    Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
                }

                return;
            }

            let Some(path) = FileDialog::new().pick_file() else {
                return;
            };
            let full_path = path.canonicalize().unwrap_or(path);
            let key_file_path = full_path.to_string_lossy().to_string();
            ui.set_key_file_path(key_file_path.clone().into());

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
                    let _ = full_path_f;
                    ui.set_status_text(PQC_SENDER_DONE.into());
                    ui.set_pqc_action_text("Open Key File".into());
                    pqc_state.step = 2;
                }
                (Err(e), _) => ui.set_generated_key_path(format!("Error writing 3.key: {e}").into()),
                (_, Err(e)) => ui.set_generated_key_path(format!("Error writing final.key: {e}").into()),
            }
        } else {
            let Some(path) = FileDialog::new().pick_file() else {
                return;
            };
            let full_path = path.canonicalize().unwrap_or(path);
            let key_file_path = full_path.to_string_lossy().to_string();
            ui.set_key_file_path(key_file_path.clone().into());

            if pqc_state.step == 0 {
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
                        ui.set_status_text(PQC_RECEIVER_STEP2.into());
                        ui.set_pqc_action_text("Open 3.key".into());
                    }
                    Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
                }

                return;
            }

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
                    let _ = full_path;
                    ui.set_status_text(PQC_RECEIVER_DONE.into());
                    ui.set_pqc_action_text("Open Key File".into());
                    pqc_state.step = 2;
                }
                Err(e) => ui.set_generated_key_path(format!("Error: {e}").into()),
            }
        }
    });

    let ui_weak = ui_handle.clone();
    let pqc_state_ref_reset = pqc_state_ref.clone();
    ui.on_reset_pqc(move || {
        let ui = ui_weak.unwrap();
        *pqc_state_ref_reset.borrow_mut() = PqcState::new();
        ui.set_key_file_path("".into());
        ui.set_generated_key_path("".into());

        if ui.get_sender() {
            ui.set_status_text(PQC_SENDER_STEP1.into());
            ui.set_pqc_action_text("Start".into());
        } else {
            ui.set_status_text(PQC_RECEIVER_STEP1.into());
            ui.set_pqc_action_text("Open 1.key".into());
        }
    });

    let ui_weak = ui_handle.clone();
    ui.on_generate_key_file(move || {
        let ui = ui_weak.unwrap();
        ui.invoke_open_key_file();
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
            ui.set_generated_password("Enter master password".into());
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
    ui.on_erase_password(move || {
        let ui = ui_weak.unwrap();
        ui.set_generated_password("".into());
        ui.set_app_name("".into());
        ui.set_app_password("".into());
        ui.set_master_password("".into());
    });

    let ui_weak = ui_handle.clone();
    ui.on_copy_password(move || {
        let ui = ui_weak.unwrap();
        let password = ui.get_generated_password().to_string();
        if password.is_empty() {
            return;
        }

        let Ok(mut ctx) = ClipboardContext::new() else {
            return;
        };
        if ctx.set_contents(password).is_err() {
            return;
        }

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(10));

            let Ok(mut ctx) = ClipboardContext::new() else {
                return;
            };

            let _ = ctx.set_contents("\0".repeat(64));
            let _ = ctx.set_contents(String::new());
        });
    });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_start_sender = secure_share_state_ref.clone();
    ui.on_secure_share_start_sender(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_start_sender.borrow_mut();

        let mode = ui.get_secure_share_mode().to_string();
        secure_share_state.set_mode(&mode);

        let text = ui.get_secure_share_text().to_string();
        let file_path = ui.get_file_path().to_string();

        let res = if mode == "text" {
            secure_share::start_sender(&mut secure_share_state, Some(text.as_str()), None)
        } else {
            secure_share::start_sender(&mut secure_share_state, None, Some(file_path.as_str()))
        };

        ui.set_secure_share_status(res.message.into());
        if let Some(p) = res.key_path {
            ui.set_generated_key_path(p.into());
        }
        if let Some(p) = res.out_path {
            ui.set_output_file_path(p.into());
        }
    });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_start_receiver = secure_share_state_ref.clone();
    ui.on_secure_share_start_receiver(move || {
        let ui = ui_weak.unwrap();
        let mut secure_share_state = secure_share_state_ref_start_receiver.borrow_mut();

        let mode = ui.get_secure_share_mode().to_string();
        let res = secure_share::start_receiver(&mut secure_share_state, &mode);

        ui.set_secure_share_status(res.message.into());
        ui.set_secure_share_action_text("Open 1.key".into());
        ui.set_key_file_path("".into());
        ui.set_generated_key_path("".into());
        ui.set_output_file_path("".into());
        ui.set_received_text("".into());
    });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_action = secure_share_state_ref.clone();
    ui.on_secure_share_action(move || {
        let ui = ui_weak.unwrap();

        let mode = ui.get_secure_share_mode().to_string();
        let is_sender = ui.get_sender();
        let text = ui.get_secure_share_text().to_string();
        let file_path = ui.get_file_path().to_string();

        let mut secure_share_state = secure_share_state_ref_action.borrow_mut();
        secure_share_state.set_mode(&mode);
        secure_share_state.set_sender(is_sender);

        if is_sender {
            if secure_share_state.step == 0 {
                let res = if mode == "text" {
                    secure_share::start_sender(&mut secure_share_state, Some(text.as_str()), None)
                } else {
                    secure_share::start_sender(&mut secure_share_state, None, Some(file_path.as_str()))
                };

                ui.set_secure_share_status(res.message.into());
                if let Some(p) = res.key_path {
                    ui.set_generated_key_path(p.into());
                }
                if let Some(p) = res.out_path {
                    ui.set_output_file_path(p.into());
                }

                if res.success {
                    ui.set_secure_share_action_text("Open 2.key".into());
                }

                return;
            }

            let Some(path) = FileDialog::new().pick_file() else {
                return;
            };
            let full_path = path.canonicalize().unwrap_or(path);
            let key_file_path = full_path.to_string_lossy().to_string();
            ui.set_key_file_path(key_file_path.clone().into());

            let res = secure_share::generate_key_with_file_path(
                &mut secure_share_state,
                &key_file_path,
                Some(file_path.as_str()),
            );

            ui.set_secure_share_status(res.message.into());
            if let Some(p) = res.key_path {
                ui.set_generated_key_path(p.into());
            }
            if let Some(p) = res.out_path {
                ui.set_output_file_path(p.into());
            }
            if let Some(t) = res.text {
                ui.set_received_text(t.into());
            }

            if res.success {
                ui.set_secure_share_action_text("Done".into());
            }
        } else {
            if secure_share_state.step <= 1 {
                let Some(path) = FileDialog::new().pick_file() else {
                    return;
                };
                let full_path = path.canonicalize().unwrap_or(path);
                let key_file_path = full_path.to_string_lossy().to_string();
                ui.set_key_file_path(key_file_path.clone().into());

                let res = secure_share::generate_key_with_file_path(&mut secure_share_state, &key_file_path, None);

                ui.set_secure_share_status(res.message.into());
                if let Some(p) = res.key_path {
                    ui.set_generated_key_path(p.into());
                }
                if let Some(p) = res.out_path {
                    ui.set_output_file_path(p.into());
                }
                if let Some(t) = res.text {
                    ui.set_received_text(t.into());
                }

                if res.success {
                    ui.set_secure_share_action_text("Open Encrypted File".into());
                }

                return;
            }

            let Some(path) = FileDialog::new().pick_file() else {
                return;
            };
            let full_path = path.canonicalize().unwrap_or(path);
            let enc_path = full_path.to_string_lossy().to_string();
            ui.set_file_path(enc_path.clone().into());

            let res = secure_share::decrypt_selected(&mut secure_share_state, &enc_path);
            ui.set_secure_share_status(res.message.into());
            if res.success {
                if mode == "text" {
                    if let Some(t) = res.text {
                        ui.set_received_text(t.into());
                    }
                } else if let Some(p) = res.out_path {
                    ui.set_output_file_path(p.into());
                }
                ui.set_secure_share_action_text("Done".into());
            }
        }
    });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_reset = secure_share_state_ref.clone();
    ui.on_secure_share_reset(move || {
        let ui = ui_weak.unwrap();
        let mode = ui.get_secure_share_mode().to_string();
        let is_sender = ui.get_sender();

        let mut secure_share_state = secure_share_state_ref_reset.borrow_mut();
        secure_share_state.reset_flow(&mode);
        secure_share_state.set_sender(is_sender);
    });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_open_key = secure_share_state_ref.clone();
    ui.on_secure_share_open_key(move || {
        let ui = ui_weak.unwrap();

        let Some(path) = FileDialog::new().pick_file() else {
            return;
        };
        let full_path = path.canonicalize().unwrap_or(path);
        let key_file_path = full_path.to_string_lossy().to_string();
        ui.set_key_file_path(key_file_path.clone().into());

        let mut secure_share_state = secure_share_state_ref_open_key.borrow_mut();
        let file_path = ui.get_file_path().to_string();

        let res = secure_share::generate_key_with_file_path(
            &mut secure_share_state,
            &key_file_path,
            Some(file_path.as_str()),
        );

        ui.set_secure_share_status(res.message.into());
        if let Some(p) = res.key_path {
            ui.set_generated_key_path(p.into());
        }
        if let Some(p) = res.out_path {
            ui.set_output_file_path(p.into());
        }
        if let Some(t) = res.text {
            ui.set_received_text(t.into());
        }
    });

    let ui_weak = ui_handle.clone();
    ui.on_secure_share_generate_key(move || {
        let ui = ui_weak.unwrap();
        ui.invoke_secure_share_open_key();
    });

     let ui_weak = ui_handle.clone();
     let secure_share_state_ref_choose = secure_share_state_ref.clone();
     ui.on_secure_share_choose_file(move || {
         let ui = ui_weak.unwrap();

         if let Some(path) = FileDialog::new().pick_file() {
             let full_path = path.canonicalize().unwrap_or(path);
             let file_path = full_path.to_string_lossy().to_string();
             ui.set_file_path(file_path.clone().into());

             let (is_sender, step, mode) = {
                let secure_share_state = secure_share_state_ref_choose.borrow();
                (secure_share_state.is_sender, secure_share_state.step, secure_share_state.mode.clone())
            };

            if is_sender {
                return;
            }

            let can_decrypt = if mode == "text" { step >= 2 } else { step >= 2 };

            if can_decrypt {
                let mut secure_share_state = secure_share_state_ref_choose.borrow_mut();
                let result = secure_share::decrypt_selected(&mut secure_share_state, &file_path);

                ui.set_secure_share_status(result.message.into());
                if result.success {
                    if mode == "text" {
                        if let Some(t) = result.text {
                            ui.set_received_text(t.into());
                        }
                    } else if let Some(p) = result.out_path {
                        ui.set_output_file_path(p.into());
                    }
                }
            } else {
                ui.set_secure_share_status("Please complete the key steps first.".into());
            }
         }
     });

    let ui_weak = ui_handle.clone();
    let secure_share_state_ref_encrypt = secure_share_state_ref.clone();
    ui.on_secure_share_encrypt(move || {
        let ui = ui_weak.unwrap();
        let file_path = ui.get_file_path().to_string();

        let secure_share_state = secure_share_state_ref_encrypt.borrow();
        let result = secure_share::encrypt_selected(&secure_share_state, &file_path);

        ui.set_secure_share_status(result.message.into());
        if let Some(path) = result.out_path {
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
                if let Some(text_content) = result.text {
                    ui.set_received_text(text_content.into());
                }
            } else if let Some(path) = result.out_path {
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
