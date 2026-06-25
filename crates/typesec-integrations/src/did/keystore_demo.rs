//! Deterministic, **non-cryptographic** demo key store for examples and tests.
//!
//! Only compiled under `cfg(test)` or the `demo-crypto` feature. Signatures are
//! forgeable by anyone holding the public key and "encryption" is a
//! repeating-key XOR; never enable `demo-crypto` in production builds.

use std::collections::HashMap;

use super::crypto::{hex_decode, hex_encode};
use super::document::VerificationMethod;
use super::error::DidError;
use super::identifier::Did;
use super::keystore::DidKeyStore;

/// Public/private key material for a local DID subject.
///
/// **Not cryptography.** Key derivation is a non-cryptographic hash and the
/// "public" key equals the private key. Tests and demos only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoDidKeyPair {
    /// Public key bytes advertised in a DID document.
    pub public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl DemoDidKeyPair {
    /// Create deterministic key material from a seed.
    pub fn from_seed(seed: impl AsRef<[u8]>) -> Self {
        let private_key = derive_bytes(b"typesec-did-private", seed.as_ref(), 32);
        let public_key = private_key.clone();
        Self {
            public_key,
            private_key,
        }
    }
}

/// Local deterministic key store for DID envelope examples and tests.
///
/// **Not cryptography**: signatures are forgeable by anyone holding the public
/// key, and "encryption" is a repeating-key XOR. Only available in tests or
/// behind the `demo-crypto` feature; use [`Ed25519DidKeyStore`] in real code.
///
/// [`Ed25519DidKeyStore`]: super::keystore::Ed25519DidKeyStore
#[derive(Debug, Default, Clone)]
pub struct DemoDidKeyStore {
    keys: HashMap<Did, DemoDidKeyPair>,
}

impl DemoDidKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key pair for a DID.
    pub fn with_key(mut self, did: Did, key: DemoDidKeyPair) -> Self {
        self.keys.insert(did, key);
        self
    }

    fn key(&self, did: &Did) -> Result<&DemoDidKeyPair, DidError> {
        self.keys
            .get(did)
            .ok_or_else(|| DidError::MissingPrivateKey(did.to_string()))
    }
}

impl DidKeyStore for DemoDidKeyStore {
    fn sign(&self, signer: &Did, message: &[u8]) -> Result<String, DidError> {
        let key = self.key(signer)?;
        Ok(hex_encode(&derive_bytes(&key.private_key, message, 32)))
    }

    fn verify(
        &self,
        method: &VerificationMethod,
        message: &[u8],
        signature: &str,
    ) -> Result<(), DidError> {
        let public = method.public_key()?;
        let expected = hex_encode(&derive_bytes(&public, message, 32));
        if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            Ok(())
        } else {
            Err(DidError::InvalidSignature)
        }
    }

    fn encrypt_for(
        &self,
        sender: &Did,
        recipient_public_key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<String, DidError> {
        let sender_key = self.key(sender)?;
        let ciphertext = xor_stream(
            plaintext,
            &derive_shared_key(
                &sender_key.private_key,
                recipient_public_key,
                nonce,
                associated_data,
            ),
        );
        Ok(hex_encode(&ciphertext))
    }

    fn decrypt_for(
        &self,
        recipient: &Did,
        sender_public_key: &[u8],
        nonce: &[u8],
        ciphertext_hex: &str,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DidError> {
        let recipient_key = self.key(recipient)?;
        let ciphertext = hex_decode(ciphertext_hex)?;
        Ok(xor_stream(
            &ciphertext,
            &derive_shared_key(
                &recipient_key.private_key,
                sender_public_key,
                nonce,
                associated_data,
            ),
        ))
    }
}

fn derive_shared_key(
    private_key: &[u8],
    public_key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(private_key.len() + public_key.len() + nonce.len());
    if private_key <= public_key {
        seed.extend_from_slice(private_key);
        seed.extend_from_slice(public_key);
    } else {
        seed.extend_from_slice(public_key);
        seed.extend_from_slice(private_key);
    }
    seed.extend_from_slice(nonce);
    seed.extend_from_slice(associated_data);
    derive_bytes(b"typesec-did-shared", &seed, 32)
}

/// Non-cryptographic FNV/xorshift expansion — demo key store only.
fn derive_bytes(domain: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0xcbf29ce484222325;
    for byte in domain.iter().chain(seed) {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545f4914f6cdd1d);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn xor_stream(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
