//! properties.rs
//!
//! Cross-module, proof-facing properties for the verification-friendly X3DH core.
//!
//! This module serves two complementary roles:
//!
//! 1. **Executable property checks**
//!    - Used in tests to validate expected behavior
//!    - Return `bool` or `Result<bool, _>`
//!
//! 2. **Formal specification layer (for hax / F*)**
//!    - Encodes protocol invariants using:
//!        - `#[hax_lib::requires]` (preconditions)
//!        - `#[hax_lib::ensures]`  (postconditions)
//!    - Provides clean proof targets for extraction
//!
//! # Structure
//!
//! The module is organized around progressively stronger properties:
//!
//! - **Local properties**
//!     - matching DH inputs → same KM
//!     - same KM → same SK
//!
//! - **Cross-module properties**
//!     - matching DH inputs → same SK
//!
//! - **Protocol consistency properties**
//!     - OPK consistency (Alice / Bob)
//!     - identity binding via associated data
//!
//! # Design notes
//!
//! - Predicates (e.g., `dh_inputs_match`) make assumptions explicit
//! - Properties use `requires(...)` to encode proof conditions
//! - Each function has a single `ensures` clause (required by hax/F*)
use crate::ad::compute_ad;
use crate::handshake_core::{
    alice_initiate_core, bob_receive_core, AliceInitiateCoreInputs, BobReceiveCoreInputs,
};
use crate::kdf::x3dh_kdf;
use crate::transcript::{assemble_km_from_alice_inputs, assemble_km_from_bob_inputs,KM_LEN_WITHOUT_OPK, KM_LEN_WITH_OPK};
use crate::types::{
    AliceDhInputs, AliceInitialMessage, BobDhInputs, BobLocalState, BobPublicContext,
    HandshakeError, X25519PublicKey,
};
use crate::state::{AliceProtocolState, BobProtocolState};

/// Predicate:
/// Alice and Bob established states agree on session outputs.
///
/// This compares the final shared secret and associated data stored
/// in the established protocol states.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    result ==
        match (alice_state, bob_state) {
            (
                AliceProtocolState::Established { result: alice_result },
                BobProtocolState::Established { result: bob_result, .. },
            ) =>
                alice_result.shared_secret == bob_result.shared_secret
                    && alice_result.associated_data == bob_result.associated_data,
            _ => false,
        }
)]
pub fn established_states_agree(
    alice_state: &AliceProtocolState,
    bob_state: &BobProtocolState,
) -> bool {
    match (alice_state, bob_state) {
        (
            AliceProtocolState::Established { result: alice_result },
            BobProtocolState::Established { result: bob_result, .. },
        ) => {
            alice_result.shared_secret == bob_result.shared_secret
                && alice_result.associated_data == bob_result.associated_data
        }
        _ => false,
    }
}

/// Property:
/// If Alice and Bob start from matching core inputs and both reach
/// `Established`, then their established states agree on session outputs.
///
/// This lifts the pure-core agreement theorem to the protocol-state layer.
///
/// It relies on:
/// - matching core inputs imply same shared secret
/// - matching core inputs imply same associated data
/// - Alice/Bob state transitions preserve the computed handshake results
#[hax_lib::include]
#[hax_lib::requires(
    core_inputs_match_for_shared_secret(alice_inputs, bob_inputs)
        && core_inputs_match_for_ad(alice_inputs, bob_inputs)
)]
#[hax_lib::ensures(|result|
    match result {
        Ok(value) => value,
        Err(_) => true,
    }
)]
pub fn prop_established_states_agree_from_matching_inputs(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> Result<bool, HandshakeError> {
    let alice_sent = crate::state::alice_start(
        crate::state::AliceProtocolState::Start,
        alice_inputs,
    )?;
    let alice_established = crate::state::alice_establish(alice_sent)?;

    let bob_received = crate::state::bob_receive(
        crate::state::BobProtocolState::Ready {
            local_state: bob_inputs.bob_state.clone(),
        },
        bob_inputs,
    )?;
    let bob_established = crate::state::bob_establish(bob_received)?;

    Ok(established_states_agree(
        &alice_established,
        &bob_established,
    ))
}

/// Predicate:
/// Alice and Bob DH inputs match positionally.
///
/// This is the key assumption for transcript consistency:
/// if this holds, both sides should assemble identical KM.
///
/// Used as a precondition (`requires`) in proof-oriented properties.
#[hax_lib::ensures(|result|
    result ==
        (alice_dh.dh1 == bob_dh.dh1
            && alice_dh.dh2 == bob_dh.dh2
            && alice_dh.dh3 == bob_dh.dh3
            && alice_dh.dh4 == bob_dh.dh4)
)]
pub fn dh_inputs_match(alice_dh: &AliceDhInputs, bob_dh: &BobDhInputs) -> bool {
    alice_dh.dh1 == bob_dh.dh1
        && alice_dh.dh2 == bob_dh.dh2
        && alice_dh.dh3 == bob_dh.dh3
        && alice_dh.dh4 == bob_dh.dh4
}

/// Predicate:
/// Alice and Bob core inputs are aligned enough to derive the same shared secret.
///
/// This assumes:
/// - Alice and Bob use positionally matching DH outputs
/// - both sides use the same HKDF info
/// - Alice's generated initial message is the one Bob receives
#[hax_lib::include]
#[hax_lib::ensures(|result|
    result ==
        (dh_inputs_match(&alice_inputs.dh_inputs, &bob_inputs.dh_inputs)
            && alice_inputs.info == bob_inputs.info
            && bob_inputs.alice_message.alice_identity_key
                == alice_inputs.alice_public.identity_key
            && bob_inputs.alice_message.alice_ephemeral_key
                == alice_inputs.alice_public.ephemeral_key
            && bob_inputs.alice_message.signed_prekey_id
                == alice_inputs.bob_public.signed_prekey.key_id
            && bob_inputs.alice_message.one_time_prekey_id
                == alice_inputs
                    .bob_public
                    .one_time_prekey
                    .as_ref()
                    .map(|opk| opk.key_id))
)]
pub fn core_inputs_match_for_shared_secret(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> bool {
    dh_inputs_match(&alice_inputs.dh_inputs, &bob_inputs.dh_inputs)
        && alice_inputs.info == bob_inputs.info
        && bob_inputs.alice_message.alice_identity_key
            == alice_inputs.alice_public.identity_key
        && bob_inputs.alice_message.alice_ephemeral_key
            == alice_inputs.alice_public.ephemeral_key
        && bob_inputs.alice_message.signed_prekey_id
            == alice_inputs.bob_public.signed_prekey.key_id
        && bob_inputs.alice_message.one_time_prekey_id
            == alice_inputs
                .bob_public
                .one_time_prekey
                .as_ref()
                .map(|opk| opk.key_id)
}

/// Property:
/// If Alice and Bob have positionally matching DH outputs,
/// they produce the same KM bytes.
#[hax_lib::requires(dh_inputs_match(alice_dh, bob_dh))]
#[hax_lib::ensures(|result| result)]
pub fn prop_matching_dh_inputs_produce_same_km(
    alice_dh: &AliceDhInputs,
    bob_dh: &BobDhInputs,
) -> bool {
    let km_alice = assemble_km_from_alice_inputs(alice_dh);
    let km_bob = assemble_km_from_bob_inputs(bob_dh);
    km_alice == km_bob
}

/// Property:
/// The X3DH KDF is deterministic:
/// same KM + same info => same SK.
#[hax_lib::include]
#[hax_lib::requires(km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK)]
#[hax_lib::ensures(|result| result)]
pub fn prop_same_km_implies_same_sk(km: &[u8], info: &[u8]) -> bool {
    match (x3dh_kdf(km, info), x3dh_kdf(km, info)) {
        (Ok(sk1), Ok(sk2)) => sk1 == sk2,
        _ => false,
    }
}

/// Property:
/// If two KM byte strings are equal, then the derived SKs are equal
/// under the same info string.
#[hax_lib::include]
#[hax_lib::requires(
    (km1.len() == KM_LEN_WITHOUT_OPK || km1.len() == KM_LEN_WITH_OPK)
        && (km2.len() == KM_LEN_WITHOUT_OPK || km2.len() == KM_LEN_WITH_OPK)
)]
#[hax_lib::ensures(|result| result == (km1 != km2 || {
    match (x3dh_kdf(km1, info), x3dh_kdf(km2, info)) {
        (Ok(sk1), Ok(sk2)) => sk1 == sk2,
        _ => false,
    }
}))]
pub fn prop_equal_km_values_imply_equal_sk(
    km1: &[u8],
    km2: &[u8],
    info: &[u8],
) -> bool {
    km1 != km2
        || match (x3dh_kdf(km1, info), x3dh_kdf(km2, info)) {
            (Ok(sk1), Ok(sk2)) => sk1 == sk2,
            _ => false,
        }
}

/// Property:
/// same Alice/Bob identity public keys imply same associated data.
///
/// Since `compute_ad` is deterministic, computing AD twice from the same
/// `(alice_identity, bob_identity)` pair must produce equal bytes.
#[hax_lib::include]
#[hax_lib::ensures(|result| result)]
pub fn prop_same_identity_keys_imply_same_ad(
    alice_identity: &X25519PublicKey,
    bob_identity: &X25519PublicKey,
) -> bool {
    let ad1 = compute_ad(alice_identity, bob_identity);
    let ad2 = compute_ad(alice_identity, bob_identity);
    ad1 == ad2
}

/// Property:
/// If Alice and Bob use matching core inputs, then the pure core derives
/// the same shared secret.
#[hax_lib::include]
#[hax_lib::requires(core_inputs_match_for_shared_secret(alice_inputs, bob_inputs))]
#[hax_lib::ensures(|result|
    match result {
        Ok(value) => value,
        Err(_) => true,
    }
)]
pub fn prop_matching_core_inputs_imply_same_shared_secret(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> Result<bool, HandshakeError> {
    let alice_result = alice_initiate_core(alice_inputs)?;
    let bob_result = bob_receive_core(bob_inputs)?;
    Ok(alice_result.shared_secret == bob_result.shared_secret)
}

/// Predicate:
/// Alice and Bob core inputs are aligned enough to compute the same AD.
///
/// This assumes Bob receives Alice's identity key and Bob's local identity
/// public key matches Alice's view of Bob's identity key.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    result ==
        (bob_inputs.alice_message.alice_identity_key
            == alice_inputs.alice_public.identity_key
            && bob_inputs.bob_state.identity_key.public_key
                == alice_inputs.bob_public.identity_key)
)]
pub fn core_inputs_match_for_ad(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> bool {
    bob_inputs.alice_message.alice_identity_key
        == alice_inputs.alice_public.identity_key
        && bob_inputs.bob_state.identity_key.public_key
            == alice_inputs.bob_public.identity_key
}

/// Property:
/// If Alice and Bob use matching core inputs, then the pure core computes
/// the same associated data.
#[hax_lib::include]
#[hax_lib::requires(core_inputs_match_for_ad(alice_inputs, bob_inputs))]
#[hax_lib::ensures(|result|
    match result {
        Ok(value) => value,
        Err(_) => true,
    }
)]
pub fn prop_matching_core_inputs_imply_same_ad(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> Result<bool, HandshakeError> {
    let alice_result = alice_initiate_core(alice_inputs)?;
    let bob_result = bob_receive_core(bob_inputs)?;
    Ok(alice_result.associated_data == bob_result.associated_data)
}

/// Property:
/// OPK consistency on the Alice side:
/// - if Bob's public bundle contains an OPK, Alice must provide DH4
/// - if Bob's public bundle does not contain an OPK, Alice must not provide DH4
pub fn prop_alice_opk_consistency(
    alice_dh: &AliceDhInputs,
    bob_public: &BobPublicContext,
) -> bool {
    let bundle_has_opk = bob_public.one_time_prekey.is_some();
    let alice_has_dh4 = alice_dh.dh4.is_some();

    bundle_has_opk == alice_has_dh4
}

/// Property:
/// OPK consistency on the Bob side:
/// - if Alice references an OPK id, Bob must have that OPK
/// - if Bob uses DH4, the ids must match
/// - if Alice does not reference an OPK, Bob must not use DH4
pub fn prop_bob_opk_consistency(
    alice_message: &AliceInitialMessage,
    bob_state: &BobLocalState,
    bob_dh: &BobDhInputs,
) -> bool {
    match (
        alice_message.one_time_prekey_id,
        bob_state.one_time_prekey.as_ref(),
        bob_dh.dh4,
    ) {
        (None, _, None) => true,
        (None, _, Some(_)) => false,
        (Some(_), None, _) => false,
        (Some(msg_id), Some(opk), Some(_)) => msg_id == opk.key_id,
        (Some(_), Some(_), None) => false,
    }
}

/// Stronger cross-module property:
/// matching Alice/Bob DH inputs imply equal KM and therefore equal SK
/// under the same info string.
#[hax_lib::include] 
#[hax_lib::requires(dh_inputs_match(alice_dh, bob_dh))]
#[hax_lib::ensures(|result| result)]
pub fn prop_matching_dh_inputs_imply_same_sk(
    alice_dh: &AliceDhInputs,
    bob_dh: &BobDhInputs,
    info: &[u8],
) -> bool {
    let km_alice = assemble_km_from_alice_inputs(alice_dh);
    let km_bob = assemble_km_from_bob_inputs(bob_dh);

    if km_alice != km_bob {
        return false;
    }

    match (x3dh_kdf(&km_alice.as_vec(), info), x3dh_kdf(&km_bob.as_vec(), info)) {
        (Ok(sk1), Ok(sk2)) => sk1 == sk2,
        _ => false,
    }
}

/// Property:
/// If Alice and Bob are provided with mutually consistent core inputs,
/// then the X3DH core produces identical session outputs on both sides.
///
/// Specifically, under matching inputs:
/// - both parties derive the same shared secret (SK)
/// - both parties compute the same associated data (AD)
///
/// This is the main *end-to-end correctness property* of the pure X3DH core.
///
/// # Intuition
///
/// - Matching DH inputs → same KM
/// - Same KM + same info → same SK
/// - Same identity keys → same AD
///
/// This property composes those guarantees across modules:
/// transcript + KDF + AD + handshake core.
///
/// # Scope
///
/// This property:
/// - assumes inputs are already consistent (via `requires(...)`)
/// - does NOT model state, key reuse, or adversarial behavior
/// - focuses purely on deterministic correctness of the core computation
///
/// This serves as the final correctness statement before introducing stateful protocol logic.
/// This corresponds to the agreement property of the X3DH handshake at the level of deterministic core computation.
#[hax_lib::include]
#[hax_lib::requires(
    core_inputs_match_for_shared_secret(alice_inputs, bob_inputs)
        && core_inputs_match_for_ad(alice_inputs, bob_inputs)
)]
#[hax_lib::ensures(|result|
    match result {
        Ok(value) => value,
        Err(_) => true,
    }
)]
pub fn prop_matching_core_inputs_imply_same_session_outputs(
    alice_inputs: &AliceInitiateCoreInputs,
    bob_inputs: &BobReceiveCoreInputs,
) -> Result<bool, HandshakeError> {
    let alice_result = alice_initiate_core(alice_inputs)?;
    let bob_result = bob_receive_core(bob_inputs)?;

    Ok(
        alice_result.shared_secret == bob_result.shared_secret
            && alice_result.associated_data == bob_result.associated_data
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::DEFAULT_INFO;
    use crate::handshake_core::{AliceInitiateCoreInputs, BobReceiveCoreInputs};
    use crate::test_helpers::{
        dh, opk_id, sample_alice_public, sample_bob_public_with_opk,
        sample_bob_public_without_opk, sample_bob_state_with_opk,
        sample_bob_state_without_opk, spk_id, xpub,
    };
    use crate::types::{
        AliceDhInputs, BobDhInputs, Ciphertext, Nonce, Plaintext,
    };

    #[test]
    fn matching_dh_inputs_produce_same_km_without_opk() {
        let alice = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: None,
        };
        let bob = BobDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: None,
        };

        assert!(prop_matching_dh_inputs_produce_same_km(&alice, &bob));
    }

    #[test]
    fn matching_dh_inputs_produce_same_km_with_opk() {
        let alice = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: Some(dh(0x04)),
        };
        let bob = BobDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: Some(dh(0x04)),
        };

        assert!(prop_matching_dh_inputs_produce_same_km(&alice, &bob));
    }

    #[test]
    fn same_km_implies_same_sk() {
        let km = vec![0x22; 96];
        assert!(prop_same_km_implies_same_sk(&km, DEFAULT_INFO));
    }

    #[test]
    fn equal_km_values_imply_equal_sk() {
        let km1 = vec![0x33; 96];
        let km2 = vec![0x33; 96];
        assert!(prop_equal_km_values_imply_equal_sk(&km1, &km2, DEFAULT_INFO));
    }

    #[test]
    fn same_identity_keys_imply_same_ad() {
        let alice = xpub(0x11);
        let bob = xpub(0x22);
        assert!(prop_same_identity_keys_imply_same_ad(&alice, &bob));
    }

    #[test]
    fn alice_opk_consistency_holds_without_opk() {
        let alice_dh = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: None,
        };
        let bob_public = sample_bob_public_without_opk();

        assert!(prop_alice_opk_consistency(&alice_dh, &bob_public));
    }

    #[test]
    fn alice_opk_consistency_holds_with_opk() {
        let alice_dh = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: Some(dh(0x04)),
        };
        let bob_public = sample_bob_public_with_opk();

        assert!(prop_alice_opk_consistency(&alice_dh, &bob_public));
    }

    #[test]
    fn bob_opk_consistency_holds_with_matching_opk() {
        let alice_message = AliceInitialMessage {
            alice_identity_key: xpub(0x11),
            alice_ephemeral_key: xpub(0x22),
            signed_prekey_id: spk_id(1001),
            one_time_prekey_id: Some(opk_id(2001)),
            nonce: Nonce([0u8; 12]),
            ciphertext: Ciphertext(vec![1, 2, 3]),
        };
        let bob_state = sample_bob_state_with_opk();
        let bob_dh = BobDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: Some(dh(0x04)),
        };

        assert!(prop_bob_opk_consistency(&alice_message, &bob_state, &bob_dh));
    }

    #[test]
    fn matching_core_inputs_imply_same_shared_secret_without_opk() {
        let alice_inputs = AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_without_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: None,
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([1u8; 12]),
            ciphertext: Ciphertext(vec![9, 9, 9]),
            info: None,
        };

        let alice_result = alice_initiate_core(&alice_inputs).unwrap();

        let bob_inputs = BobReceiveCoreInputs {
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
        };

        assert!(prop_matching_core_inputs_imply_same_shared_secret(
            &alice_inputs,
            &bob_inputs
        )
        .unwrap());

        assert!(prop_matching_core_inputs_imply_same_ad(
            &alice_inputs,
            &bob_inputs
        )
        .unwrap());
    }

    #[test]
    fn matching_dh_inputs_imply_same_sk() {
        let alice = AliceDhInputs {
            dh1: dh(0xaa),
            dh2: dh(0xbb),
            dh3: dh(0xcc),
            dh4: None,
        };
        let bob = BobDhInputs {
            dh1: dh(0xaa),
            dh2: dh(0xbb),
            dh3: dh(0xcc),
            dh4: None,
        };

        assert!(prop_matching_dh_inputs_imply_same_sk(
            &alice,
            &bob,
            DEFAULT_INFO
        ));
    }
}
