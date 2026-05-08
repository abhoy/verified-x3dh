//! ad.rs
//!
//! Associated-data construction for a verification-friendly X3DH core.
//!
//! In this model:
//!   AD = Encode(IK_A) || Encode(IK_B)
//!
//! where Encode(PK) = curve_tag || raw_x25519_public_key

use crate::types::{
    EncodedX25519PublicKey, X25519PublicKey, CURVE_TAG_X25519, X25519_KEY_LEN,
};

/// Length of one encoded X25519 public key:
///   1-byte curve tag + 32-byte raw public key
pub const ENCODED_X25519_PUBLIC_KEY_LEN: usize = 1 + X25519_KEY_LEN;

/// Length of associated data:
///   Encode(IK_A) || Encode(IK_B)
pub const ASSOCIATED_DATA_LEN: usize = 2 * ENCODED_X25519_PUBLIC_KEY_LEN;

/// Associated-data bytes:
///   Encode(IK_A) || Encode(IK_B)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssociatedDataBytes(pub [u8; ASSOCIATED_DATA_LEN]);

/// Returns true when an encoded X25519 public key has the expected curve tag.
#[hax_lib::ensures(|result| result == (encoded.0[0] == CURVE_TAG_X25519))]
pub fn has_valid_curve_tag(encoded: &EncodedX25519PublicKey) -> bool {
    encoded.0[0] == CURVE_TAG_X25519
}

/// Returns true when associated data has the expected X3DH length.
#[hax_lib::ensures(|result| result == (ad.0.len() == ASSOCIATED_DATA_LEN))]
pub fn is_valid_ad(ad: &AssociatedDataBytes) -> bool {
    ad.0.len() == ASSOCIATED_DATA_LEN
}

/// Encode an X25519 public key in the application-defined X3DH format.
///
/// Format:
///   curve_tag || raw_public_key
///
/// For this model:
///   curve_tag = 0x05
#[hax_lib::ensures(|result| result.0.len() == ENCODED_X25519_PUBLIC_KEY_LEN)]
///    result.0[0] == CURVE_TAG_X25519
///        && result.0.len() == ENCODED_X25519_PUBLIC_KEY_LEN
///)]
pub fn encode_x25519_public_key(pubkey: &X25519PublicKey) -> EncodedX25519PublicKey {
    let mut encoded = [0u8; ENCODED_X25519_PUBLIC_KEY_LEN];
    encoded[0] = CURVE_TAG_X25519;
    encoded[1..].copy_from_slice(&pubkey.0);
    EncodedX25519PublicKey(encoded)
}

/// Compute associated data:
///   AD = Encode(IK_A) || Encode(IK_B)
///
/// This binds the initiator and responder identities to the encrypted
/// initial message.
#[hax_lib::ensures(|result| is_valid_ad(&result))]
///        && result.0[..ENCODED_X25519_PUBLIC_KEY_LEN]
///            == encode_x25519_public_key(alice_identity_key).0
///        && result.0[ENCODED_X25519_PUBLIC_KEY_LEN..]
///            == encode_x25519_public_key(bob_identity_key).0
///)]
pub fn compute_ad(
    alice_identity_key: &X25519PublicKey,
    bob_identity_key: &X25519PublicKey,
) -> AssociatedDataBytes {
    let alice_encoded = encode_x25519_public_key(alice_identity_key);
    let bob_encoded = encode_x25519_public_key(bob_identity_key);

    let mut ad = [0u8; ASSOCIATED_DATA_LEN];
    ad[..ENCODED_X25519_PUBLIC_KEY_LEN].copy_from_slice(&alice_encoded.0);
    ad[ENCODED_X25519_PUBLIC_KEY_LEN..].copy_from_slice(&bob_encoded.0);

    AssociatedDataBytes(ad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::xpub as pk;

    #[test]
    fn encode_x25519_public_key_has_expected_length() {
        let key = pk(0x11);
        let encoded = encode_x25519_public_key(&key);
        assert_eq!(encoded.0.len(), ENCODED_X25519_PUBLIC_KEY_LEN);
    }

    #[test]
    fn encode_x25519_public_key_starts_with_curve_tag() {
        let key = pk(0x22);
        let encoded = encode_x25519_public_key(&key);
        assert_eq!(encoded.0[0], CURVE_TAG_X25519);
    }

    #[test]
    fn encode_x25519_public_key_contains_raw_key_bytes() {
        let key = pk(0x33);
        let encoded = encode_x25519_public_key(&key);

        assert_eq!(encoded.0[1..], key.0);
    }

    #[test]
    fn compute_ad_has_expected_length() {
        let alice = pk(0xaa);
        let bob = pk(0xbb);

        let ad = compute_ad(&alice, &bob);
        assert_eq!(ad.0.len(), ASSOCIATED_DATA_LEN);
    }

    #[test]
    fn compute_ad_is_deterministic() {
        let alice = pk(0x01);
        let bob = pk(0x02);

        let ad1 = compute_ad(&alice, &bob);
        let ad2 = compute_ad(&alice, &bob);

        assert_eq!(ad1, ad2);
    }

    #[test]
    fn compute_ad_changes_when_identity_changes() {
        let alice1 = pk(0x10);
        let alice2 = pk(0x11);
        let bob = pk(0x20);

        let ad1 = compute_ad(&alice1, &bob);
        let ad2 = compute_ad(&alice2, &bob);

        assert_ne!(ad1, ad2);
    }

    #[test]
    fn compute_ad_respects_order_of_identities() {
        let alice = pk(0x44);
        let bob = pk(0x55);

        let ad_ab = compute_ad(&alice, &bob);
        let ad_ba = compute_ad(&bob, &alice);

        assert_ne!(ad_ab, ad_ba);
    }

    #[test]
    fn compute_ad_places_alice_then_bob() {
        let alice = pk(0xa1);
        let bob = pk(0xb2);

        let ad = compute_ad(&alice, &bob);
        let alice_encoded = encode_x25519_public_key(&alice);
        let bob_encoded = encode_x25519_public_key(&bob);

        assert_eq!(
            &ad.0[..ENCODED_X25519_PUBLIC_KEY_LEN],
            &alice_encoded.0
        );
        assert_eq!(
            &ad.0[ENCODED_X25519_PUBLIC_KEY_LEN..],
            &bob_encoded.0
        );
    }

    #[test]
    fn encoded_key_has_valid_curve_tag() {
        let key = pk(0x77);
        let encoded = encode_x25519_public_key(&key);
        assert!(has_valid_curve_tag(&encoded));
    }

    #[test]
    fn computed_ad_is_valid() {
        let alice = pk(0x12);
        let bob = pk(0x34);

        let ad = compute_ad(&alice, &bob);
        assert!(is_valid_ad(&ad));
    }
}