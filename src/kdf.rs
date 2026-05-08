//! kdf.rs
//!
//! HKDF and X3DH key derivation for a verification-friendly core model.
//!
//! This module models:
//! - HKDF-Extract
//! - HKDF-Expand
//! - X3DH KDF:
//!     SK = HKDF(salt = 0^32, ikm = F || KM, info)
//!
//! where for X25519:
//!     F = 0xFF repeated 32 times
//!
//! # Verification structure
//!
//! This file uses an abstract HMAC model. The goal here is not to verify
//! concrete HMAC-SHA256, but to verify protocol-level KDF structure and
//! length properties.
//!
//! HKDF-Expand is split into:
//! - `hkdf_expand`: checked public wrapper
//! - `hkdf_expand_valid`: proof-oriented helper for valid lengths
//!
//! This allows us to prove:
//! - successful HKDF-Expand returns exactly `length` bytes
//! - invalid lengths are rejected
//! - X3DH KDF returns a 32-byte shared secret

use crate::types::{SharedSecret, SHARED_SECRET_LEN};
use crate::transcript::{KM_LEN_WITHOUT_OPK, KM_LEN_WITH_OPK};

/// SHA-256 output size in bytes.
pub const HASH_LEN: usize = 32;

/// Maximum RFC 5869 HKDF-Expand output length.
pub const MAX_HKDF_OUTPUT_LEN: usize = 255 * HASH_LEN;

/// X3DH discontinuity bytes for X25519: 32 bytes of 0xFF.
pub const F_25519: [u8; HASH_LEN] = [0xFF; HASH_LEN];

/// Zero salt used by the X3DH KDF.
pub const ZERO_SALT: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Default X3DH application/context string.
pub const DEFAULT_INFO: &[u8] = b"MyApp_X3DH_X25519_SHA256";

/// Abstract HMAC-SHA256 model.
///
/// In the verification core, we only rely on the fact that HMAC-SHA256
/// returns exactly 32 bytes. Concrete cryptographic behavior belongs in a
/// separate adapter layer.
fn hmac_sha256(_key: &[u8], _data: &[u8]) -> [u8; HASH_LEN] {
    [0u8; HASH_LEN]
}

/// HKDF pseudorandom key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudorandomKey(pub [u8; HASH_LEN]);

/// HKDF output key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputKeyMaterial(pub Vec<u8>);

/// Errors returned by KDF operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfError {
    InvalidLength,
    LengthTooLarge,
}

/// Returns true when an HKDF output length is valid under RFC 5869.
#[hax_lib::ensures(|result| result == (length > 0 && length <= MAX_HKDF_OUTPUT_LEN))]
pub fn is_valid_hkdf_output_len(length: usize) -> bool {
    length > 0 && length <= MAX_HKDF_OUTPUT_LEN
}

/// Returns true when a byte string length matches the SHA-256 output size.
#[hax_lib::ensures(|result| result == (len == HASH_LEN))]
pub fn is_hash_len(len: usize) -> bool {
    len == HASH_LEN
}

/// Build X3DH input key material:
///   ikm = F_25519 || km
#[hax_lib::requires(km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK)]
#[hax_lib::ensures(|result| result.len() == HASH_LEN + km.len())]
pub fn build_x3dh_ikm(km: &[u8]) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(HASH_LEN + km.len());
    ikm.extend_from_slice(&F_25519);
    ikm.extend_from_slice(km);
    ikm
}

/// HKDF-Extract.
///
/// Proof-facing model:
/// returns a 32-byte pseudorandom key.
#[hax_lib::include]
#[hax_lib::ensures(|result| is_hash_len(result.0.len()))]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> PseudorandomKey {
    PseudorandomKey(hmac_sha256(salt, ikm))
}

/// Internal HKDF-Expand helper for valid lengths.
///
/// This helper is the main proof target for HKDF-Expand length correctness.
#[hax_lib::include]
#[hax_lib::requires(length > 0 && length <= MAX_HKDF_OUTPUT_LEN)]
#[hax_lib::ensures(|result| result.0.len() == length)]
fn hkdf_expand_valid(
    _prk: &PseudorandomKey,
    _info: &[u8],
    length: usize,
) -> OutputKeyMaterial {
    OutputKeyMaterial(vec![0u8; length])
}

/// HKDF-Expand checked wrapper.
///
/// Guarantees:
/// - `Ok(okm)` implies `okm.0.len() == length`
/// - `Err(InvalidLength)` implies `length == 0`
/// - `Err(LengthTooLarge)` implies `length > MAX_HKDF_OUTPUT_LEN`
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(okm) =>
            okm.0.len() == length
                && is_valid_hkdf_output_len(length),
        Err(KdfError::InvalidLength) => length == 0,
        Err(KdfError::LengthTooLarge) => length > MAX_HKDF_OUTPUT_LEN,
    }
)]
pub fn hkdf_expand(
    prk: &PseudorandomKey,
    info: &[u8],
    length: usize,
) -> Result<OutputKeyMaterial, KdfError> {
    if length == 0 {
        return Err(KdfError::InvalidLength);
    }

    if length > MAX_HKDF_OUTPUT_LEN {
        return Err(KdfError::LengthTooLarge);
    }

    Ok(hkdf_expand_valid(prk, info, length))
}

/// X3DH shared-secret derivation.
///
/// Per X3DH for X25519 + SHA-256:
///   SK = HKDF(
///       salt = 0^32,
///       ikm  = F_25519 || KM,
///       info = application-specific context
///   )
///
/// Guarantees:
/// - If successful, returns a 32-byte shared secret.
#[hax_lib::include]
#[hax_lib::requires(km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK)]
#[hax_lib::ensures(|result|
    match result {
        Ok(sk) => sk.0.len() == SHARED_SECRET_LEN,
        Err(_) => false,
    }
)]
pub fn x3dh_kdf(km: &[u8], info: &[u8]) -> Result<SharedSecret, KdfError> {
    let ikm = build_x3dh_ikm(km);
    let prk = hkdf_extract(&ZERO_SALT, &ikm);
    let okm = hkdf_expand(&prk, info, HASH_LEN)?;

    let mut sk = [0u8; HASH_LEN];
    sk.copy_from_slice(&okm.0);

    Ok(SharedSecret(sk))
}

/// X3DH shared-secret derivation using the default context string.
#[hax_lib::requires(km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK)]
#[hax_lib::ensures(|result|
    match result {
        Ok(sk) => sk.0.len() == SHARED_SECRET_LEN,
        Err(_) => false,
    }
)]
pub fn x3dh_kdf_default(km: &[u8]) -> Result<SharedSecret, KdfError> {
    x3dh_kdf(km, DEFAULT_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_extract_returns_32_bytes() {
        let salt = [0x00; HASH_LEN];
        let ikm = b"input key material";
        let prk = hkdf_extract(&salt, ikm);
        assert_eq!(prk.0.len(), HASH_LEN);
    }

    #[test]
    fn hkdf_expand_returns_requested_length() {
        let prk = PseudorandomKey([0x11; HASH_LEN]);
        let info = b"context";
        let okm = hkdf_expand(&prk, info, 32).unwrap();
        assert_eq!(okm.0.len(), 32);
    }

    #[test]
    fn hkdf_expand_rejects_zero_length() {
        let prk = PseudorandomKey([0x11; HASH_LEN]);
        let info = b"context";
        let result = hkdf_expand(&prk, info, 0);
        assert_eq!(result, Err(KdfError::InvalidLength));
    }

    #[test]
    fn hkdf_expand_rejects_too_large_length() {
        let prk = PseudorandomKey([0x11; HASH_LEN]);
        let info = b"context";
        let result = hkdf_expand(&prk, info, MAX_HKDF_OUTPUT_LEN + 1);
        assert_eq!(result, Err(KdfError::LengthTooLarge));
    }

    #[test]
    fn build_x3dh_ikm_has_expected_length_without_opk() {
        let km = vec![0x22; 96];
        let ikm = build_x3dh_ikm(&km);
        assert_eq!(ikm.len(), HASH_LEN + 96);
    }

    #[test]
    fn build_x3dh_ikm_has_expected_length_with_opk() {
        let km = vec![0x22; 128];
        let ikm = build_x3dh_ikm(&km);
        assert_eq!(ikm.len(), HASH_LEN + 128);
    }

    #[test]
    fn x3dh_kdf_returns_32_byte_shared_secret_without_opk() {
        let km = vec![0x42; 96];
        let sk = x3dh_kdf_default(&km).unwrap();
        assert_eq!(sk.0.len(), HASH_LEN);
    }

    #[test]
    fn x3dh_kdf_returns_32_byte_shared_secret_with_opk() {
        let km = vec![0x42; 128];
        let sk = x3dh_kdf_default(&km).unwrap();
        assert_eq!(sk.0.len(), HASH_LEN);
    }
}