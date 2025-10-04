use super::constants_errors::*;
use super::symmetric::argon2id_hash;
use std::collections::HashMap;

const MAX_PASSWORD_LEN: usize = 128;

struct PasswordGenerator {
    required_sets: HashMap<&'static str, &'static str>,
    optional_sets: HashMap<&'static str, &'static str>,
}

impl PasswordGenerator {
    // MARK: new
    fn new() -> Self {
        let mut required_sets = HashMap::new();
        required_sets.insert("lowercase", "abcdefghijklmnopqrstuvwxyz");
        required_sets.insert("uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        required_sets.insert("numbers", "0123456789");

        let mut optional_sets = HashMap::new();
        optional_sets.insert("symbols_basic", "!@#$%^&*");
        optional_sets.insert("symbols_extended", "()_+-=[]{}|;:");
        optional_sets.insert("symbols_special", ",.<>?/~`");

        Self { required_sets, optional_sets }
    }

    // MARK: hkdf
    fn hkdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut salt_array = [0u8; 32];
        let copy_len = salt.len().min(32);
        salt_array[..copy_len].copy_from_slice(&salt[..copy_len]);
        let prk = argon2id_hash(ikm, &salt_array, 32, 1024, 1, 1)
            .unwrap_or_else(|_| vec![0u8; 32]);
        let mut output = Vec::new();
        let mut counter = 1u8;
        while output.len() < len {
            let mut input = prk.clone();
            input.extend_from_slice(info);
            input.push(counter);
            
            let mut info_salt = [0u8; 32];
            let info_len = info.len().min(32);
            info_salt[..info_len].copy_from_slice(&info[..info_len]);
            
            let block = argon2id_hash(&input, &info_salt, 32, 1024, 1, 1)
                .unwrap_or_else(|_| vec![0u8; 32]);
            output.extend_from_slice(&block);
            counter += 1;
        }
        output.truncate(len);
        output
    }

    // MARK: unbiased_select
    fn unbiased_select(&self, mut value: u32, max: usize) -> usize {
        let threshold = u32::MAX - (u32::MAX % max as u32);
        while value >= threshold {
            let salt = *b"bias_elimination_salt_32_bytes__";
            let hash = argon2id_hash(&value.to_be_bytes(), &salt, 4, 1024, 1, 1)
                .unwrap_or_else(|_| vec![0u8; 4]);
            value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        }
        (value % max as u32) as usize
    }

    // MARK: shuffle
    fn shuffle(&self, mut chars: Vec<char>, key: &[u8]) -> String {
        for i in (1..chars.len()).rev() {
            let info = format!("shuffle_{}", i).into_bytes();
            let bytes = self.hkdf(b"shuffle_salt", key, &info, 4);
            let j_val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let j = self.unbiased_select(j_val, i + 1);
            chars.swap(i, j);
        }
        chars.into_iter().collect()
    }

    // MARK: generate
    fn generate(&self, input_hash: &[u8], length: usize, optional_sets: Option<&[&str]>) -> Result<String, CryptoError> {
        if input_hash.len() != 128 || length < 3 || length > MAX_PASSWORD_LEN {
            return Err(CryptoError::InvalidInput);
        }

        let mut active_sets = self.required_sets.clone();
        if let Some(sets) = optional_sets {
            for &set_name in sets {
                if let Some(&charset) = self.optional_sets.get(set_name) {
                    active_sets.insert(set_name, charset);
                }
            }
        }

        let domain_salt = b"PQrypt_Password_Generation_2024";
        let mut password_chars = Vec::with_capacity(length);
        
        // Sort keys for deterministic iteration order
        let mut sorted_keys: Vec<_> = active_sets.keys().collect();
        sorted_keys.sort();
        
        for (i, &set_name) in sorted_keys.iter().enumerate() {
            let charset = active_sets.get(set_name).unwrap();
            let info = format!("required_{}_{}", set_name, i).into_bytes();
            let bytes = self.hkdf(domain_salt, input_hash, &info, 4);
            let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let index = self.unbiased_select(value, charset.len());
            password_chars.push(charset.chars().nth(index).unwrap());
        }
        
        // Build all_chars in sorted order for consistency
        let mut all_chars = String::new();
        for &key in &sorted_keys {
            all_chars.push_str(active_sets.get(key).unwrap());
        }
        for position in active_sets.len()..length {
            let info = format!("char_{}", position).into_bytes();
            let bytes = self.hkdf(domain_salt, input_hash, &info, 4);
            let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let index = self.unbiased_select(value, all_chars.len());
            password_chars.push(all_chars.chars().nth(index).unwrap());
        }

        Ok(self.shuffle(password_chars, input_hash))
    }
}

// MARK: generate_password
pub fn generate_password(
    _mode: u8,
    hash_bytes: &[u8],
    desired_len: usize,
    enabled_symbol_sets: &[bool; 3]
) -> Option<String> {
    if hash_bytes.is_empty() || desired_len == 0 || desired_len > MAX_PASSWORD_LEN {
        return None;
    }
    
    let mut hash_128 = vec![0u8; 128];
    if hash_bytes.len() >= 128 {
        hash_128.copy_from_slice(&hash_bytes[..128]);
    } else {
        for i in 0..128 {
            hash_128[i] = hash_bytes[i % hash_bytes.len()];
        }
    }
    let mut optional_sets = Vec::new();
    if enabled_symbol_sets[0] { optional_sets.push("symbols_basic"); }
    if enabled_symbol_sets[1] { optional_sets.push("symbols_extended"); }
    if enabled_symbol_sets[2] { optional_sets.push("symbols_special"); }
    
    let generator = PasswordGenerator::new();
    let optional_sets_ref = if optional_sets.is_empty() { None } else { Some(optional_sets.as_slice()) };
    
    generator.generate(&hash_128, desired_len, optional_sets_ref).ok()
}

// MARK: derive_password_hash_secure
pub fn derive_password_hash_secure(
    _app_name: &str,
    app_password: &str,
    master_password: &str,
    salt_source: &str
) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; 32];
    let salt_bytes = salt_source.as_bytes();
    let copy_len = salt_bytes.len().min(32);
    salt[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);
    
    let first_hash = argon2id_hash(master_password.as_bytes(), &salt, 64, 10240, 1, 1)?;
    
    if !app_password.is_empty() {
        let mut app_salt = [0u8; 32];
        let app_salt_bytes = app_password.as_bytes();
        let app_copy_len = app_salt_bytes.len().min(32);
        app_salt[..app_copy_len].copy_from_slice(&app_salt_bytes[..app_copy_len]);
        argon2id_hash(&first_hash, &app_salt, 64, 10240, 1, 1)
    } else {
        Ok(first_hash)
    }
}
