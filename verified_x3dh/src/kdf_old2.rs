//! kdf.rs
//!
//! HKDF and X3DH key derivation for a verification-friendly core model.
//!
//! This module implements:
//! - HKDF-Extract (HMAC-SHA256)
//! - HKDF-Expand  (HMAC-SHA256)
//! - X3DH KDF:
//!     SK = HKDF(salt = 0^32, ikm = F || KM, info)
//!
//! where for X25519:
//!     F = 0xFF repeated 32 times
//!
//! # Verification structure
//!
//! To make formal reasoning tractable, HKDF-Expand is split into:
//! - a checked wrapper (`hkdf_expand`) that handles invalid inputs
//! - a proof-oriented helper (`hkdf_expand_valid`) that assumes valid inputs
//!
//! This separation isolates:
//! - input validation and error handling
//! - iterative cryptographic computation (HKDF loop)
//!
//! and enables modular reasoning about each part.
//!
//! # Proof notes
//!
//! - `hkdf_expand_valid` isolates loop reasoning from error handling
//! - length correctness is proved at the helper level
//! - the wrapper ensures correct mapping from invalid inputs to errors
//!
//! The helper function is the primary proof target for HKDF-Expand,
//! while the wrapper provides a clean, total API.
//!
//! # Proven properties (intended)
//!
//! - HKDF-Extract always returns a 32-byte pseudorandom key
//! - HKDF-Expand returns exactly `length` bytes when successful
//! - HKDF-Expand rejects invalid lengths correctly
//! - X3DH KDF returns a 32-byte shared secret
//! - X3DH KDF is deterministic (same inputs → same output)

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::types::{SharedSecret, SHARED_SECRET_LEN};

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

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
///
/// This is separated from the HKDF call so the X3DH-specific assembly
/// can be reasoned about independently.
#[hax_lib::ensures(|result| result.len() == HASH_LEN + km.len())]
pub fn build_x3dh_ikm(km: &[u8]) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(F_25519.len() + km.len());
    ikm.extend_from_slice(&F_25519);
    ikm.extend_from_slice(km);
    ikm
}

/// HKDF-Extract using HMAC-SHA256.
///
/// RFC 5869:
///   PRK = HMAC(salt, IKM)
///
/// Returns a 32-byte pseudorandom key.
#[hax_lib::include]
#[hax_lib::ensures(|result| is_hash_len(result.0.len()))]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> PseudorandomKey {
    let mut mac =
        HmacSha256::new_from_slice(salt).expect("HMAC accepts arbitrary key sizes");
    mac.update(ikm);
    let result = mac.finalize().into_bytes();

    let mut prk = [0u8; HASH_LEN];
    prk.copy_from_slice(&result);
    PseudorandomKey(prk)
}

/// Internal HKDF-Expand helper with validated inputs.
///
/// This function assumes:
/// - `length > 0`
/// - `length <= MAX_HKDF_OUTPUT_LEN`
///
/// It performs the iterative HKDF expansion:
///   T(1) = HMAC(PRK, info || 0x01)
///   T(2) = HMAC(PRK, T(1) || info || 0x02)
///   ...
///
/// and concatenates blocks until at least `length` bytes are produced,
/// then truncates to exactly `length`.
///
/// # Proof role
///
/// This function is the primary verification target for HKDF-Expand.
///
/// It is designed so that we can prove:
///   result.0.len() == length
///
/// under the given preconditions.
///
/// The public `hkdf_expand` function delegates to this helper
/// after validating inputs.
#[hax_lib::requires(length > 0 && length <= MAX_HKDF_OUTPUT_LEN)]
#[hax_lib::ensures(|result| result.0.len() == length)]
fn hkdf_expand_valid(
    prk: &PseudorandomKey,
    info: &[u8],
    length: usize,
) -> OutputKeyMaterial {
    let mut okm = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < length {
        // Loop progress:
        // Each iteration appends one 32-byte block (HASH_LEN),
        // so okm.len() strictly increases until it reaches `length`.
        //
        // Decreases measure for termination:
        //     length - okm.len()
        hax_lib::loop_decreases!(length - okm.len());

        let mut mac =
            HmacSha256::new_from_slice(&prk.0).expect("HMAC accepts arbitrary key sizes");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);

        let block = mac.finalize().into_bytes();
        previous = block.to_vec();
        okm.extend_from_slice(&previous);

        counter = counter.wrapping_add(1);
    }

    okm.truncate(length);
    OutputKeyMaterial(okm)
}

/// HKDF-Expand using HMAC-SHA256.
///
/// RFC 5869:
///   OKM = HKDF-Expand(PRK, info, length)
///
/// This function is split into two layers:
///
/// - `hkdf_expand`:
///     * validates the requested output length
///     * returns an error for invalid inputs
///
/// - `hkdf_expand_valid`:
///     * assumes valid inputs
///     * performs the actual HKDF expansion
///     * is the main proof target
///
/// # Guarantees
///
/// - If `Ok(okm)` is returned:
///     * `okm.0.len() == length`
/// - If `Err(InvalidLength)`:
///     * `length == 0`
/// - If `Err(LengthTooLarge)`:
///     * `length > MAX_HKDF_OUTPUT_LEN`
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
/// # Guarantees
///
/// - If successful, returns a 32-byte shared secret
/// - Deterministic:
///     same KM + same info => same SK
///
/// # Verification role
///
/// Relies on:
/// - `build_x3dh_ikm` correctness
/// - `hkdf_extract` length correctness
/// - `hkdf_expand` length correctness
#[hax_lib::include]
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
    fn build_x3dh_ikm_has_expected_length() {
        let km = vec![0x22; 96];
        let ikm = build_x3dh_ikm(&km);
        assert_eq!(ikm.len(), HASH_LEN + 96);
    }

    #[test]
    fn x3dh_kdf_is_deterministic() {
        let km = vec![0x22; 96];
        let sk1 = x3dh_kdf(&km, DEFAULT_INFO).unwrap();
        let sk2 = x3dh_kdf(&km, DEFAULT_INFO).unwrap();
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn x3dh_kdf_changes_when_km_changes() {
        let km1 = vec![0x22; 96];
        let km2 = vec![0x23; 96];

        let sk1 = x3dh_kdf(&km1, DEFAULT_INFO).unwrap();
        let sk2 = x3dh_kdf(&km2, DEFAULT_INFO).unwrap();

        assert_ne!(sk1, sk2);
    }

    #[test]
    fn x3dh_kdf_changes_when_info_changes() {
        let km = vec![0x22; 96];

        let sk1 = x3dh_kdf(&km, b"context-1").unwrap();
        let sk2 = x3dh_kdf(&km, b"context-2").unwrap();

        assert_ne!(sk1, sk2);
    }

    #[test]
    fn x3dh_kdf_returns_32_byte_shared_secret() {
        let km = vec![0x42; 96];
        let sk = x3dh_kdf_default(&km).unwrap();
        assert_eq!(sk.0.len(), HASH_LEN);
    }
}
