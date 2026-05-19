//! handshake_core.rs
//!
//! Pure X3DH handshake core over abstract inputs.
//!
//! This module does not perform:
//! - Diffie-Hellman
//! - signature verification
//! - AEAD encryption/decryption
//! - randomness
//!
//! Instead, it assumes those values are already available and focuses on:
//! - protocol consistency checks
//! - KM assembly
//! - shared-secret derivation
//! - associated-data construction
//! - message/result construction

use crate::ad::{compute_ad, AssociatedDataBytes};
use crate::kdf::{x3dh_kdf, DEFAULT_INFO};
use crate::transcript::{
    assemble_km_from_alice_inputs, assemble_km_from_bob_inputs,
};
use crate::types::{
    AliceDhInputs, AliceHandshakeResult, AliceInitialMessage, AlicePublicContext,
    AssociatedData, BobDhInputs, BobHandshakeResult, BobLocalState, BobPublicContext,
    Ciphertext, HandshakeError, Nonce, Plaintext,
};

/// Alice-side core inputs.
///
/// These are the pure protocol inputs needed after the crypto layer has:
/// - verified Bob's signed prekey signature
/// - generated Alice's ephemeral key
/// - computed DH outputs
/// - encrypted the initial payload
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliceInitiateCoreInputs {
    /// Alice public context.
    pub alice_public: AlicePublicContext,

    /// Bob public bundle/context.
    pub bob_public: BobPublicContext,

    /// Alice-side DH outputs in X3DH order.
    pub dh_inputs: AliceDhInputs,

    /// Result of signed-prekey authentication from the crypto layer.
    pub signed_prekey_is_valid: bool,

    /// AEAD nonce produced by the crypto layer.
    pub nonce: Nonce,

    /// AEAD ciphertext produced by the crypto layer.
    pub ciphertext: Ciphertext,

    /// Optional HKDF info string override.
    ///
    /// If `None`, DEFAULT_INFO is used.
    pub info: Option<Vec<u8>>,
}

/// Bob-side core inputs.
///
/// These are the pure protocol inputs needed after the crypto layer has:
/// - parsed Alice's initial message
/// - computed Bob-side DH outputs
/// - decrypted the ciphertext
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobReceiveCoreInputs {
    /// Bob's local prekey state.
    pub bob_state: BobLocalState,

    /// Alice's received initial message.
    pub alice_message: AliceInitialMessage,

    /// Bob-side DH outputs in X3DH order.
    pub dh_inputs: BobDhInputs,

    /// Decrypted plaintext from the crypto layer.
    pub plaintext: Plaintext,

    /// Optional HKDF info string override.
    ///
    /// If `None`, DEFAULT_INFO is used.
    pub info: Option<Vec<u8>>,
}

/// Internal helper: choose either the provided HKDF info or the default.
fn selected_info(info: &Option<Vec<u8>>) -> &[u8] {
    match info {
        Some(v) => v.as_slice(),
        None => DEFAULT_INFO,
    }
}

/// Returns true when Bob's bundle contains a one-time prekey.
fn bob_public_has_opk(inputs: &BobPublicContext) -> bool {
    inputs.one_time_prekey.is_some()
}

/// Returns true when Alice's DH transcript includes the optional fourth DH.
fn alice_has_dh4(inputs: &AliceDhInputs) -> bool {
    inputs.dh4.is_some()
}

/// Internal helper: ensure Alice's view of OPK usage is self-consistent.
///
/// Policy in this model:
/// - if Bob advertises an OPK, Alice must use it
/// - if Bob does not advertise an OPK, Alice must not provide DH4
fn validate_alice_opk_consistency(inputs: &AliceInitiateCoreInputs) -> Result<(), HandshakeError> {
    let bundle_has_opk = bob_public_has_opk(&inputs.bob_public);
    let alice_uses_opk = alice_has_dh4(&inputs.dh_inputs);

    if bundle_has_opk != alice_uses_opk {
        return Err(HandshakeError::MalformedMessage);
    }

    Ok(())
}

/// Internal helper: ensure Bob can reconstruct the referenced prekeys.
fn validate_bob_message_consistency(inputs: &BobReceiveCoreInputs) -> Result<(), HandshakeError> {
    if inputs.alice_message.signed_prekey_id != inputs.bob_state.signed_prekey.key_id {
        return Err(HandshakeError::UnknownSignedPreKeyId);
    }

    match (
        inputs.alice_message.one_time_prekey_id.clone(),
        inputs.bob_state.one_time_prekey.as_ref(),
        inputs.dh_inputs.dh4,
    ) {
        (None, None, None) => Ok(()),
        (None, Some(_), None) => Ok(()),
        (Some(_), None, _) => Err(HandshakeError::UnknownOneTimePreKeyId),
        (Some(msg_id), Some(opk), Some(_)) if msg_id == opk.key_id => Ok(()),
        (Some(_), Some(_), None) => Err(HandshakeError::MalformedMessage),
        (Some(_), Some(_), Some(_)) => Err(HandshakeError::UnknownOneTimePreKeyId),
        (None, _, Some(_)) => Err(HandshakeError::MalformedMessage),
    }
}

/// Convert fixed-length AD bytes into the broader protocol AD wrapper.
fn wrap_associated_data(ad: AssociatedDataBytes) -> AssociatedData {
    AssociatedData(ad.0.to_vec())
}

/// Alice-side pure handshake logic.
///
/// This function:
/// - checks signed-prekey validity
/// - checks OPK consistency
/// - assembles KM
/// - derives the shared secret
/// - computes AD
/// - constructs Alice's initial message
pub fn alice_initiate_core(
    inputs: &AliceInitiateCoreInputs,
) -> Result<AliceHandshakeResult, HandshakeError> {
    if !inputs.signed_prekey_is_valid {
        return Err(HandshakeError::InvalidSignedPreKeySignature);
    }

    validate_alice_opk_consistency(inputs)?;

    let km = assemble_km_from_alice_inputs(&inputs.dh_inputs);
    let shared_secret =
        x3dh_kdf(&km.as_vec(), selected_info(&inputs.info))
            .map_err(|_| HandshakeError::MalformedMessage)?;

    let associated_data = wrap_associated_data(compute_ad(
        &inputs.alice_public.identity_key,
        &inputs.bob_public.identity_key,
    ));

    let initial_message = AliceInitialMessage {
        alice_identity_key: inputs.alice_public.identity_key,
        alice_ephemeral_key: inputs.alice_public.ephemeral_key,
        signed_prekey_id: inputs.bob_public.signed_prekey.key_id.clone(),
        one_time_prekey_id: inputs.bob_public.one_time_prekey.as_ref().map(|opk| opk.key_id),
        nonce: inputs.nonce,
        ciphertext: inputs.ciphertext.clone(),
    };

    Ok(AliceHandshakeResult {
        initial_message,
        shared_secret,
        associated_data,
    })
}

/// Bob-side pure handshake logic.
///
/// This function:
/// - checks the referenced prekey identifiers
/// - checks OPK consistency
/// - assembles KM
/// - derives the shared secret
/// - computes AD
/// - returns the reconstructed handshake result
///
/// Note:
/// - This function does not perform AEAD decryption itself.
/// - `plaintext` is assumed to come from a crypto adapter layer.
pub fn bob_receive_core(
    inputs: &BobReceiveCoreInputs,
) -> Result<BobHandshakeResult, HandshakeError> {
    validate_bob_message_consistency(inputs)?;

    let km = assemble_km_from_bob_inputs(&inputs.dh_inputs);
    let shared_secret =
        x3dh_kdf(&km.as_vec(), selected_info(&inputs.info))
            .map_err(|_| HandshakeError::MalformedMessage)?;

    let associated_data = wrap_associated_data(compute_ad(
        &inputs.alice_message.alice_identity_key,
        &inputs.bob_state.identity_key.public_key,
    ));

    Ok(BobHandshakeResult {
        shared_secret,
        associated_data,
        plaintext: inputs.plaintext.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use crate::types::{AliceDhInputs, BobDhInputs, Ciphertext, Nonce, Plaintext};

    #[test]
    fn alice_initiate_core_rejects_invalid_signature() {
        let inputs = AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_without_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: None,
            },
            signed_prekey_is_valid: false,
            nonce: Nonce([0u8; 12]),
            ciphertext: Ciphertext(vec![0xaa, 0xbb]),
            info: None,
        };

        let result = alice_initiate_core(&inputs);
        assert_eq!(result, Err(HandshakeError::InvalidSignedPreKeySignature));
    }

    #[test]
    fn alice_initiate_core_succeeds_without_opk() {
        let inputs = AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_without_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: None,
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([7u8; 12]),
            ciphertext: Ciphertext(vec![0xaa, 0xbb, 0xcc]),
            info: None,
        };

        let result = alice_initiate_core(&inputs).unwrap();
        assert_eq!(result.initial_message.signed_prekey_id, spk_id(1001));
        assert_eq!(result.initial_message.one_time_prekey_id, None);
        assert_eq!(result.initial_message.nonce, Nonce([7u8; 12]));
        assert_eq!(result.initial_message.ciphertext, Ciphertext(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn alice_initiate_core_succeeds_with_opk() {
        let inputs = AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_with_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: Some(dh(0x04)),
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([9u8; 12]),
            ciphertext: Ciphertext(vec![0xdd]),
            info: None,
        };

        let result = alice_initiate_core(&inputs).unwrap();
        assert_eq!(result.initial_message.one_time_prekey_id, Some(opk_id(2001)));
    }

    #[test]
    fn bob_receive_core_rejects_wrong_signed_prekey_id() {
        let inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: AliceInitialMessage {
                alice_identity_key: xpub(0x11),
                alice_ephemeral_key: xpub(0x22),
                signed_prekey_id: spk_id(9999),
                one_time_prekey_id: None,
                nonce: Nonce([0u8; 12]),
                ciphertext: Ciphertext(vec![1, 2, 3]),
            },
            dh_inputs: BobDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: None,
            },
            plaintext: Plaintext(b"hello".to_vec()),
            info: None,
        };

        let result = bob_receive_core(&inputs);
        assert_eq!(result, Err(HandshakeError::UnknownSignedPreKeyId));
    }

    #[test]
    fn bob_receive_core_succeeds_without_opk() {
        let inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: AliceInitialMessage {
                alice_identity_key: xpub(0x11),
                alice_ephemeral_key: xpub(0x22),
                signed_prekey_id: spk_id(1001),
                one_time_prekey_id: None,
                nonce: Nonce([1u8; 12]),
                ciphertext: Ciphertext(vec![4, 5, 6]),
            },
            dh_inputs: BobDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: None,
            },
            plaintext: Plaintext(b"hello".to_vec()),
            info: None,
        };

        let result = bob_receive_core(&inputs).unwrap();
        assert_eq!(result.plaintext, Plaintext(b"hello".to_vec()));
    }

    #[test]
    fn alice_and_bob_derive_same_shared_secret_without_opk() {
        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_without_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: None,
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([3u8; 12]),
            ciphertext: Ciphertext(vec![9, 9, 9]),
            info: None,
        })
        .unwrap();

        let bob_result = bob_receive_core(&BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: alice_result.initial_message.clone(),
            dh_inputs: BobDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: None,
            },
            plaintext: Plaintext(b"ok".to_vec()),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn alice_and_bob_derive_same_shared_secret_with_opk() {
        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_with_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: Some(dh(0x40)),
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([4u8; 12]),
            ciphertext: Ciphertext(vec![8, 8, 8]),
            info: None,
        })
        .unwrap();

        let bob_result = bob_receive_core(&BobReceiveCoreInputs {
            bob_state: sample_bob_state_with_opk(),
            alice_message: alice_result.initial_message.clone(),
            dh_inputs: BobDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: Some(dh(0x40)),
            },
            plaintext: Plaintext(b"ok".to_vec()),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }
}