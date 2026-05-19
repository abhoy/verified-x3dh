//! test_helpers.rs
//!
//! Shared test helpers for X3DH core unit/integration-style tests.

use crate::types::{
    AlicePublicContext, BobLocalState, BobPublicContext, DhOutput, Ed25519PublicKey,
    IdentityKeyPair, IdentitySigningPublicKey, OneTimePreKeyId, OneTimePreKeyPair,
    OneTimePreKeyPublic, Signature, SignedPreKeyId, SignedPreKeyPair, SignedPreKeyPublic,
    X25519PrivateKey, X25519PublicKey,
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
    SignedPreKeyId::new(x).expect("test SPK id should be valid")
}

pub fn opk_id(x: u32) -> OneTimePreKeyId {
    OneTimePreKeyId::new(x).expect("test OPK id should be valid")
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