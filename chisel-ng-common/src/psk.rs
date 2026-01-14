//! Pre-shared key handling for authentication
//!
//! The PSK is used to authenticate clients to the server.
//! Both sides must have the same key configured.

use sha2::{Sha256, Digest};
use rand::Rng;
use std::fmt;

/// A pre-shared key for authentication
#[derive(Clone)]
pub struct PresharedKey {
    key: Vec<u8>,
}

impl PresharedKey {
    /// Create a new PSK from raw bytes
    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Create a new PSK from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let key = hex::decode(hex_str)?;
        Ok(Self { key })
    }

    /// Create a new PSK from a passphrase (hashed with SHA-256)
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let key = hasher.finalize().to_vec();
        Self { key }
    }

    /// Generate a random 32-byte PSK
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill(&mut key[..]);
        Self { key }
    }

    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get the key as a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }

    /// Get a fingerprint of the key (first 8 bytes as hex)
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }

    /// Verify that two PSKs match using constant-time comparison
    pub fn verify(&self, other: &PresharedKey) -> bool {
        // Length check (not constant-time, but lengths should always match)
        if self.key.len() != other.key.len() {
            return false;
        }

        // XOR all bytes and OR the results - prevents timing attacks
        // Execution time is constant regardless of where mismatch occurs
        let mut result = 0u8;
        for (a, b) in self.key.iter().zip(other.key.iter()) {
            result |= a ^ b;  // Accumulate any bit differences
        }
        result == 0  // Zero means all bytes matched
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose the actual key in debug output
        write!(f, "PresharedKey(fingerprint={})", self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_from_passphrase() {
        let psk1 = PresharedKey::from_passphrase("test");
        let psk2 = PresharedKey::from_passphrase("test");
        assert!(psk1.verify(&psk2));
    }

    #[test]
    fn test_psk_different() {
        let psk1 = PresharedKey::from_passphrase("test1");
        let psk2 = PresharedKey::from_passphrase("test2");
        assert!(!psk1.verify(&psk2));
    }

    #[test]
    fn test_psk_hex_roundtrip() {
        let psk1 = PresharedKey::generate();
        let hex = psk1.to_hex();
        let psk2 = PresharedKey::from_hex(&hex).unwrap();
        assert!(psk1.verify(&psk2));
    }
}
