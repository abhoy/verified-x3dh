//! demo_inputs.rs
//!
//! Reusable non-test sample inputs for running the verification-friendly X3DH
//! core as a demo or example.
//!
//! These values are intentionally deterministic and abstract. They are useful
//! for driving `handshake_core` and `state` APIs, but they are not concrete
//! cryptographic test vectors.

use crate::handshake_core::{AliceInitiateCoreInputs, BobReceiveCoreInputs};
use crate::types::{
    AliceDhInputs, AlicePublicContext, BobDhInputs, BobLocalState, BobPublicContext,
    Ciphertext, DhOutput, Ed25519PublicKey, IdentityKeyPair, IdentitySigningPublicKey,
    Nonce, OneTimePreKeyId, OneTimePreKeyPair, OneTimePreKeyPublic, Plaintext,
    Signature, SignedPreKeyId, SignedPreKeyPair, SignedPreKeyPublic, X25519PrivateKey,
    X25519PublicKey,
};

pub fn xpub(byte: u8) -> X25519PublicKey {
    X25519PublicKey([byte; 32])
}

pub fn xpriv(byte: u8) -> X25519PrivateKey {
    X25519PrivateKey([byte; 32])
}

pub fn edpub(byte: u8) -> Ed25519PublicKey {
    Ed25519PublicKey([byte; 32])
}

pub fn sig(byte: u8) -> Signature {
    Signature([byte; 64])
}

pub fn dh(byte: u8) -> DhOutput {
    DhOutput([byte; 32])
}

pub fn spk_id(x: u32) -> SignedPreKeyId {
    SignedPreKeyId::new(x).expect("demo SPK id should be valid")
}

pub fn opk_id(x: u32) -> OneTimePreKeyId {
    OneTimePreKeyId::new(x).expect("demo OPK id should be valid")
}

pub fn sample_alice_public() -> AlicePublicContext {
    AlicePublicContext {
        identity_key: xpub(0x11),
        ephemeral_key: xpub(0x22),
    }
}

pub fn sample_bob_public_without_opk() -> BobPublicContext {
    BobPublicContext {
        identity_key: xpub(0x33),
        signed_prekey: SignedPreKeyPublic {
            key_id: spk_id(1001),
            public_key: xpub(0x44),
            signature: sig(0x91),
        },
        one_time_prekey: None,
    }
}

pub fn sample_bob_public_with_opk() -> BobPublicContext {
    BobPublicContext {
        identity_key: xpub(0x33),
        signed_prekey: SignedPreKeyPublic {
            key_id: spk_id(1001),
            public_key: xpub(0x44),
            signature: sig(0x91),
        },
        one_time_prekey: Some(OneTimePreKeyPublic {
            key_id: opk_id(2001),
            public_key: xpub(0x55),
        }),
    }
}

pub fn sample_bob_state_without_opk() -> BobLocalState {
    BobLocalState {
        identity_key: IdentityKeyPair {
            private_key: xpriv(0x61),
            public_key: xpub(0x33),
        },
        signing_key: IdentitySigningPublicKey {
            public_key: edpub(0x71),
        },
        signed_prekey: SignedPreKeyPair {
            key_id: spk_id(1001),
            private_key: xpriv(0x81),
            public_key: xpub(0x44),
            signature: sig(0x91),
        },
        one_time_prekey: None,
    }
}

pub fn sample_bob_state_with_opk() -> BobLocalState {
    BobLocalState {
        identity_key: IdentityKeyPair {
            private_key: xpriv(0x61),
            public_key: xpub(0x33),
        },
        signing_key: IdentitySigningPublicKey {
            public_key: edpub(0x71),
        },
        signed_prekey: SignedPreKeyPair {
            key_id: spk_id(1001),
            private_key: xpriv(0x81),
            public_key: xpub(0x44),
            signature: sig(0x91),
        },
        one_time_prekey: Some(OneTimePreKeyPair {
            key_id: opk_id(2001),
            private_key: xpriv(0xa1),
            public_key: xpub(0x55),
        }),
    }
}

pub fn sample_alice_dh_without_opk() -> AliceDhInputs {
    AliceDhInputs {
        dh1: dh(0x10),
        dh2: dh(0x20),
        dh3: dh(0x30),
        dh4: None,
    }
}

pub fn sample_bob_dh_without_opk() -> BobDhInputs {
    BobDhInputs {
        dh1: dh(0x10),
        dh2: dh(0x20),
        dh3: dh(0x30),
        dh4: None,
    }
}

pub fn sample_alice_dh_with_opk() -> AliceDhInputs {
    AliceDhInputs {
        dh1: dh(0x10),
        dh2: dh(0x20),
        dh3: dh(0x30),
        dh4: Some(dh(0x40)),
    }
}

pub fn sample_bob_dh_with_opk() -> BobDhInputs {
    BobDhInputs {
        dh1: dh(0x10),
        dh2: dh(0x20),
        dh3: dh(0x30),
        dh4: Some(dh(0x40)),
    }
}

pub fn sample_alice_core_inputs_without_opk() -> AliceInitiateCoreInputs {
    AliceInitiateCoreInputs {
        alice_public: sample_alice_public(),
        bob_public: sample_bob_public_without_opk(),
        dh_inputs: sample_alice_dh_without_opk(),
        signed_prekey_is_valid: true,
        nonce: Nonce([1u8; 12]),
        ciphertext: Ciphertext(vec![0xaa, 0xbb, 0xcc]),
        info: None,
    }
}

pub fn sample_alice_core_inputs_with_opk() -> AliceInitiateCoreInputs {
    AliceInitiateCoreInputs {
        alice_public: sample_alice_public(),
        bob_public: sample_bob_public_with_opk(),
        dh_inputs: sample_alice_dh_with_opk(),
        signed_prekey_is_valid: true,
        nonce: Nonce([2u8; 12]),
        ciphertext: Ciphertext(vec![0xdd, 0xee]),
        info: None,
    }
}

pub fn sample_bob_core_inputs_without_opk() -> BobReceiveCoreInputs {
    let alice_inputs = sample_alice_core_inputs_without_opk();

    BobReceiveCoreInputs {
        bob_state: sample_bob_state_without_opk(),
        alice_message: crate::handshake_core::alice_initiate_core(&alice_inputs)
            .expect("demo Alice inputs should produce a message")
            .initial_message,
        dh_inputs: sample_bob_dh_without_opk(),
        plaintext: Plaintext(b"hello".to_vec()),
        info: None,
    }
}

pub fn sample_bob_core_inputs_with_opk() -> BobReceiveCoreInputs {
    let alice_inputs = sample_alice_core_inputs_with_opk();

    BobReceiveCoreInputs {
        bob_state: sample_bob_state_with_opk(),
        alice_message: crate::handshake_core::alice_initiate_core(&alice_inputs)
            .expect("demo Alice inputs should produce a message")
            .initial_message,
        dh_inputs: sample_bob_dh_with_opk(),
        plaintext: Plaintext(b"with-opk".to_vec()),
        info: None,
    }
}
