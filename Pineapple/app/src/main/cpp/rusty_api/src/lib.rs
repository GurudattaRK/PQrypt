//! This library provides both Rust-native APIs and C FFI bindings
//! for cross-language compatibility.

pub mod rusty_api;
pub mod c_ffi;

// Re-export for easier access
pub use rusty_api::*;
pub use c_ffi::*;

// Custom random number generator for Android
pub fn android_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // Use /dev/urandom for Android
    use std::fs::File;
    use std::io::Read;
    
    let mut file = File::open("/dev/urandom")
        .map_err(|_| getrandom::Error::UNSUPPORTED)?;
    file.read_exact(buf)
        .map_err(|_| getrandom::Error::UNSUPPORTED)?;
    Ok(())
}
