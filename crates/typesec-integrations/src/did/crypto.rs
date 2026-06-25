//! Production crypto and encoding helpers shared across the `did` submodules.

use std::time::{SystemTime, UNIX_EPOCH};

use super::error::DidError;
use super::typedid::TypeDidConversation;

pub(super) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// Domain-separated SHA-256: `SHA-256(domain || 0x00 || data)`.
pub(super) fn sha256_tagged(domain: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(data);
    hasher.finalize().into()
}

/// A fresh random 12-byte AEAD nonce from the OS RNG.
pub(super) fn random_nonce() -> Result<[u8; 12], DidError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| DidError::KeyGen(e.to_string()))?;
    Ok(nonce)
}

pub(super) fn canonical_typedid_conversation(conversation: &TypeDidConversation) -> String {
    format!(
        "{}\n{:?}\n{}\n{}\n{}",
        conversation.conversation_id,
        conversation.mode,
        conversation.profile,
        conversation.protocol,
        conversation
            .expires_at
            .map(|expires_at| expires_at.to_string())
            .unwrap_or_default()
    )
}

pub(super) fn contains(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

pub(super) fn intersects(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.contains(value))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>, DidError> {
    if !value.len().is_multiple_of(2) {
        return Err(DidError::InvalidHex);
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, DidError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DidError::InvalidHex),
    }
}
