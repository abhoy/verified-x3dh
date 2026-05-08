//! tests.rs
//!
//! Cross-module integration-style tests for the verification-friendly X3DH core.

#[cfg(test)]
mod tests {
    use crate::ad::{compute_ad, ASSOCIATED_DATA_LEN};
    use crate::handshake_core::{
        alice_initiate_core, bob_receive_core, AliceInitiateCoreInputs, BobReceiveCoreInputs,
    };
    use crate::kdf::{x3dh_kdf_default, DEFAULT_INFO};
    use crate::test_helpers::*;
    use crate::transcript::{
        assemble_km_from_alice_inputs, assemble_km_from_bob_inputs, expected_km_len,
        is_valid_km_len,
    };
    use crate::types::{
        AliceDhInputs, AliceInitialMessage, BobDhInputs, Ciphertext, Nonce, Plaintext,
    };

    #[test]
    fn end_to_end_without_opk_agrees_on_km_sk_and_ad() {
        let alice_dh = AliceDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x20),
            dh3: dh(0x30),
            dh4: None,
        };

        let bob_dh = BobDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x20),
            dh3: dh(0x30),
            dh4: None,
        };

        let km_alice = assemble_km_from_alice_inputs(&alice_dh);
        let km_bob = assemble_km_from_bob_inputs(&bob_dh);

        assert_eq!(km_alice, km_bob);
        assert_eq!(km_alice.len(), expected_km_len(false));
        assert!(is_valid_km_len(&km_alice.as_vec()));

        let sk_alice = x3dh_kdf_default(&km_alice.as_vec()).unwrap();
        let sk_bob = x3dh_kdf_default(&km_bob.as_vec()).unwrap();
        assert_eq!(sk_alice, sk_bob);

        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_without_opk(),
            dh_inputs: alice_dh,
            signed_prekey_is_valid: true,
            nonce: Nonce([1u8; 12]),
            ciphertext: Ciphertext(vec![0xaa, 0xbb, 0xcc]),
            info: None,
        })
        .unwrap();

        let bob_result = bob_receive_core(&BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: alice_result.initial_message.clone(),
            dh_inputs: bob_dh,
            plaintext: Plaintext(b"hello".to_vec()),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.shared_secret, sk_alice);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
        assert_eq!(alice_result.associated_data.0.len(), ASSOCIATED_DATA_LEN);
        assert_eq!(bob_result.plaintext, Plaintext(b"hello".to_vec()));
    }

    #[test]
    fn end_to_end_with_opk_agrees_on_km_sk_and_ad() {
        let alice_dh = AliceDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x20),
            dh3: dh(0x30),
            dh4: Some(dh(0x40)),
        };

        let bob_dh = BobDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x20),
            dh3: dh(0x30),
            dh4: Some(dh(0x40)),
        };

        let km_alice = assemble_km_from_alice_inputs(&alice_dh);
        let km_bob = assemble_km_from_bob_inputs(&bob_dh);

        assert_eq!(km_alice, km_bob);
        assert_eq!(km_alice.len(), expected_km_len(true));
        assert!(is_valid_km_len(&km_alice.as_vec()));

        let sk_alice = x3dh_kdf_default(&km_alice.as_vec()).unwrap();
        let sk_bob = x3dh_kdf_default(&km_bob.as_vec()).unwrap();
        assert_eq!(sk_alice, sk_bob);

        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_with_opk(),
            dh_inputs: alice_dh,
            signed_prekey_is_valid: true,
            nonce: Nonce([2u8; 12]),
            ciphertext: Ciphertext(vec![0xdd, 0xee]),
            info: None,
        })
        .unwrap();

        let bob_result = bob_receive_core(&BobReceiveCoreInputs {
            bob_state: sample_bob_state_with_opk(),
            alice_message: alice_result.initial_message.clone(),
            dh_inputs: bob_dh,
            plaintext: Plaintext(b"with-opk".to_vec()),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.shared_secret, sk_alice);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
        assert_eq!(bob_result.plaintext, Plaintext(b"with-opk".to_vec()));
    }

    #[test]
    fn associated_data_matches_direct_computation() {
        let alice = sample_alice_public();
        let bob = sample_bob_public_without_opk();

        let ad_direct = compute_ad(&alice.identity_key, &bob.identity_key);

        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: alice,
            bob_public: bob,
            dh_inputs: AliceDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: None,
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([0u8; 12]),
            ciphertext: Ciphertext(vec![0x99]),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.associated_data.0, ad_direct.0.to_vec());
    }

    #[test]
    fn mismatched_dh_inputs_produce_different_km() {
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
            ciphertext: Ciphertext(vec![0x01, 0x02]),
            info: Some(DEFAULT_INFO.to_vec()),
        })
        .unwrap();

        let alice_km = assemble_km_from_alice_inputs(&AliceDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x20),
            dh3: dh(0x30),
            dh4: None,
        });

        let bob_dh = BobDhInputs {
            dh1: dh(0x10),
            dh2: dh(0x99),
            dh3: dh(0x30),
            dh4: None,
        };
        let bob_km = assemble_km_from_bob_inputs(&bob_dh);

        let bob_result = bob_receive_core(&BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: alice_result.initial_message.clone(),
            dh_inputs: bob_dh,
            plaintext: Plaintext(b"broken".to_vec()),
            info: Some(DEFAULT_INFO.to_vec()),
        })
        .unwrap();

        assert_ne!(alice_km, bob_km);
        assert_eq!(bob_result.plaintext, Plaintext(b"broken".to_vec()));
    }

    #[test]
    fn alice_message_carries_expected_key_ids() {
        let alice_result = alice_initiate_core(&AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_with_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: Some(dh(0x04)),
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([8u8; 12]),
            ciphertext: Ciphertext(vec![0xfa, 0xfb]),
            info: None,
        })
        .unwrap();

        assert_eq!(alice_result.initial_message.signed_prekey_id, spk_id(1001));
        assert_eq!(alice_result.initial_message.one_time_prekey_id, Some(opk_id(2001)));
    }

    #[test]
    fn bob_rejects_unknown_one_time_prekey_id() {
        let inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_with_opk(),
            alice_message: AliceInitialMessage {
                alice_identity_key: xpub(0x11),
                alice_ephemeral_key: xpub(0x22),
                signed_prekey_id: spk_id(1001),
                one_time_prekey_id: Some(opk_id(9999)),
                nonce: Nonce([0u8; 12]),
                ciphertext: Ciphertext(vec![1, 2, 3]),
            },
            dh_inputs: BobDhInputs {
                dh1: dh(0x01),
                dh2: dh(0x02),
                dh3: dh(0x03),
                dh4: Some(dh(0x04)),
            },
            plaintext: Plaintext(b"hello".to_vec()),
            info: None,
        };

        let result = bob_receive_core(&inputs);
        assert!(result.is_err());
    }
}
