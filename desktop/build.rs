use std::env;
use std::path::PathBuf;

fn main() {
    slint_build::compile("ui/main.slint").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OQS_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");

    let custom_openssl_base = env::var("PQRYPT_CUSTOM_OPENSSL_DIR").ok().map(PathBuf::from);
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok().map(PathBuf::from);
    let repo_root = manifest_dir.as_deref().and_then(|p| p.parent()).map(PathBuf::from);

    let oqs_dir = env::var("OQS_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let mut candidates = Vec::new();
            if let Some(r) = &repo_root {
                candidates.push(r.join("Openssl/static_libs/liboqs-0.15"));
                candidates.push(r.join("Openssl/liboqs/build"));
            }
            if let Some(b) = &custom_openssl_base {
                candidates.push(b.join("static_libs/liboqs-0.15"));
                candidates.push(b.join("liboqs/build"));
            }
            candidates.into_iter().find(|p| p.join("lib/liboqs.a").exists())
        });

    if let Some(oqs_dir) = oqs_dir {
        let oqs_lib_dir = oqs_dir.join("lib");
        println!("cargo:rustc-link-search=native={}", oqs_lib_dir.display());
        println!("cargo:rustc-link-lib=static=oqs");
    } else {
        panic!("liboqs not found. Build static deps into <repo>/Openssl/static_libs or set PQRYPT_CUSTOM_OPENSSL_DIR to your Openssl folder or set OQS_DIR to a prefix containing lib/liboqs.a");
    }

    if env::var("OPENSSL_STATIC").is_ok() {
        let openssl_dir = env::var("OPENSSL_DIR")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                let mut candidates = Vec::new();
                if let Some(r) = &repo_root {
                    candidates.push(r.join("Openssl/static_libs/openssl-3.6"));
                }
                if let Some(b) = &custom_openssl_base {
                    candidates.push(b.join("static_libs/openssl-3.6"));
                }
                candidates
                    .into_iter()
                    .find(|p| p.join("lib/libssl.a").exists() && p.join("lib/libcrypto.a").exists())
            });

        if let Some(openssl_dir) = openssl_dir {
            let openssl_lib_dir = openssl_dir.join("lib");
            println!("cargo:rustc-link-search=native={}", openssl_lib_dir.display());
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
        } else {
            panic!("OPENSSL_STATIC is set but OpenSSL static libs not found. Build static deps into <repo>/Openssl/static_libs or set PQRYPT_CUSTOM_OPENSSL_DIR to your Openssl folder or set OPENSSL_DIR to a prefix containing lib/libssl.a and lib/libcrypto.a");
        }
    }
}