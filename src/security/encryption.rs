use std::path::Path;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use colored::Colorize;

pub fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AEAD encryption failed");
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    B64.encode(&combined)
}

pub fn decrypt_data(key: &[u8; 32], encoded: &str) -> Option<Vec<u8>> {
    let combined = B64.decode(encoded).ok()?;
    if combined.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

pub fn get_data_key(key_path: &Path, generate_if_missing: bool) -> Result<[u8; 32], String> {
    if let Ok(hex_key) = std::env::var("CLEWDR_DATA_KEY") {
        let hex_key = hex_key.trim();
        if hex_key.is_empty() {
            return Err("CLEWDR_DATA_KEY is set but empty".into());
        }
        let bytes = hex::decode(hex_key)
            .map_err(|_| "CLEWDR_DATA_KEY is not valid hex".to_string())?;
        let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "CLEWDR_DATA_KEY must be 32 bytes (64 hex chars), got {}",
                v.len()
            )
        })?;
        return Ok(key);
    }

    if key_path.exists() {
        let content = std::fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read {}: {e}", key_path.display()))?;
        let bytes = hex::decode(content.trim())
            .map_err(|_| format!("{} contains invalid hex", key_path.display()))?;
        let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "{} must contain 32 bytes (64 hex chars), got {}",
                key_path.display(),
                v.len()
            )
        })?;
        return Ok(key);
    }

    if !generate_if_missing {
        return Err(format!(
            "Encrypted cookies found but no data key available.\n\
             Set CLEWDR_DATA_KEY env var or create {}",
            key_path.display()
        ));
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let hex_key = hex::encode(key);
    std::fs::write(key_path, &hex_key)
        .map_err(|e| format!("Failed to write key file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }
    println!(
        "{}: {}",
        "Data key generated".green(),
        key_path.display().to_string().blue()
    );
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let plaintext = b"hello world cookies";
        let encrypted = encrypt_data(&key, plaintext);
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        OsRng.fill_bytes(&mut key1);
        OsRng.fill_bytes(&mut key2);
        let encrypted = encrypt_data(&key1, b"secret");
        assert!(decrypt_data(&key2, &encrypted).is_none());
    }

    #[test]
    fn test_corrupted_data_fails() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        assert!(decrypt_data(&key, "not-valid-base64!!!").is_none());
        assert!(decrypt_data(&key, &B64.encode(b"tooshort")).is_none());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let plaintext = b"same data";
        let enc1 = encrypt_data(&key, plaintext);
        let enc2 = encrypt_data(&key, plaintext);
        assert_ne!(enc1, enc2);
        assert_eq!(
            decrypt_data(&key, &enc1).unwrap(),
            decrypt_data(&key, &enc2).unwrap()
        );
    }
}
