//! types.rs
//!
//! Verification-friendly core types for an X3DH-style handshake model.
//!
//! Design goals:
//! - keep the core free of concrete crypto implementations
//! - make invalid protocol states harder to represent
//! - use explicit wrappers for role-specific data
//! - keep message/public-state structure close to the proof model
//! - make extension to PQXDH straightforward

/// Length of X25519 public keys, private keys, and DH outputs in bytes.
pub const X25519_KEY_LEN: usize = 32;

/// Length of Ed25519 public keys in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of Ed25519 signatures in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of a derived shared secret / AEAD key in this model.
pub const SHARED_SECRET_LEN: usize = 32;

/// Length of the X3DH "F" prefix for X25519.
pub const DISCONTINUITY_LEN: usize = 32;

/// Length of an AEAD nonce.
pub const NONCE_LEN: usize = 12;

/// Length of an encoded X25519 public key: curve tag || raw key.
pub const ENCODED_X25519_PUBLIC_KEY_LEN: usize = 1 + X25519_KEY_LEN;

/// Application-defined single-byte key type tag used by Encode(PK).
pub const CURVE_TAG_X25519: u8 = 0x05;

/// Optional proof-oriented bound for key identifiers.
pub const MAX_PREKEY_ID: u32 = 1_000_000;

/// Raw X25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; X25519_KEY_LEN]);

/// Raw X25519 private key.
///
/// In the verification core, this is just a byte wrapper.
/// Real crypto operations belong in an adapter layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PrivateKey(pub [u8; X25519_KEY_LEN]);

/// Raw Ed25519 public key used to verify signed prekey signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_LEN]);

/// Raw Ed25519 signature bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; ED25519_SIGNATURE_LEN]);

/// Raw 32-byte Diffie-Hellman output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhOutput(pub [u8; X25519_KEY_LEN]);

/// Raw 32-byte handshake shared secret / AEAD key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedSecret(pub [u8; SHARED_SECRET_LEN]);

/// AEAD nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

/// A serialized public key in the application-defined X3DH encoding.
///
/// For X25519:
///   Encode(PK) = curve_tag || raw_public_key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedX25519PublicKey(pub [u8; ENCODED_X25519_PUBLIC_KEY_LEN]);

/// Key identifier for Bob's signed prekey.
#[hax_lib::attributes]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedPreKeyId {
    #[hax_lib::refine(v < MAX_PREKEY_ID)]
    pub v: u32,
}

impl SignedPreKeyId {
    //pub fn new(v: u32) -> Self {
    //    Self { v }
    //}
     pub fn new(v: u32) -> Option<Self> {
        if v < MAX_PREKEY_ID {
            Some(Self { v })
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.v
    }
}

/// Key identifier for Bob's one-time prekey.
#[hax_lib::attributes]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OneTimePreKeyId {
    #[hax_lib::refine(v < MAX_PREKEY_ID)]
    pub v: u32,
}

impl OneTimePreKeyId {
    //pub fn new(v: u32) -> Self {
    //    Self { v }
    //}
     pub fn new(v: u32) -> Option<Self> {
        if v < MAX_PREKEY_ID {
            Some(Self { v })
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.v
    }
}

/// Ciphertext bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(pub Vec<u8>);

/// Plaintext bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plaintext(pub Vec<u8>);

/// Associated data bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociatedData(pub Vec<u8>);

/// Long-term identity key pair used for X25519 DH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityKeyPair {
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
}

/// Long-term signing public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentitySigningPublicKey {
    pub public_key: Ed25519PublicKey,
}

/// Public portion of a signed prekey record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPreKeyPublic {
    pub key_id: SignedPreKeyId,
    pub public_key: X25519PublicKey,
    pub signature: Signature,
}

/// Full signed prekey pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPreKeyPair {
    pub key_id: SignedPreKeyId,
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
    pub signature: Signature,
}

/// Public portion of a one-time prekey record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimePreKeyPublic {
    pub key_id: OneTimePreKeyId,
    pub public_key: X25519PublicKey,
}

/// Full one-time prekey pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimePreKeyPair {
    pub key_id: OneTimePreKeyId,
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
}

/// Bob's published prekey bundle as seen by Alice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobPreKeyBundle {
    pub identity_key: X25519PublicKey,
    pub signing_key: Ed25519PublicKey,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<OneTimePreKeyPublic>,
}

/// Alice's first protocol message to Bob.
#[hax_lib::attributes]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliceInitialMessage {
    pub alice_identity_key: X25519PublicKey,
    pub alice_ephemeral_key: X25519PublicKey,
    pub signed_prekey_id: SignedPreKeyId,
    pub one_time_prekey_id: Option<OneTimePreKeyId>,
    pub nonce: Nonce,
    pub ciphertext: Ciphertext,
}

/// Result of Alice's initiation step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliceHandshakeResult {
    pub initial_message: AliceInitialMessage,
    pub shared_secret: SharedSecret,
    pub associated_data: AssociatedData,
}

/// Result of Bob's receive step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobHandshakeResult {
    pub shared_secret: SharedSecret,
    pub associated_data: AssociatedData,
    pub plaintext: Plaintext,
}

/// Alice-side DH inputs after the crypto adapter has evaluated them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AliceDhInputs {
    pub dh1: DhOutput,
    pub dh2: DhOutput,
    pub dh3: DhOutput,
    pub dh4: Option<DhOutput>,
}

/// Bob-side DH inputs after the crypto adapter has evaluated them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BobDhInputs {
    pub dh1: DhOutput,
    pub dh2: DhOutput,
    pub dh3: DhOutput,
    pub dh4: Option<DhOutput>,
}

/// Alice-side public values needed by the core handshake logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlicePublicContext {
    pub identity_key: X25519PublicKey,
    pub ephemeral_key: X25519PublicKey,
}

/// Bob-side public values needed by the core handshake logic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobPublicContext {
    pub identity_key: X25519PublicKey,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<OneTimePreKeyPublic>,
}

/// Verification-friendly local Bob state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobLocalState {
    pub identity_key: IdentityKeyPair,
    pub signing_key: IdentitySigningPublicKey,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekey: Option<OneTimePreKeyPair>,
}

/// High-level handshake errors for the core model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidSignedPreKeySignature,
    UnknownSignedPreKeyId,
    UnknownOneTimePreKeyId,
    InvalidAssociatedData,
    DecryptionFailed,
    MalformedMessage,
}

/// High-level state for Alice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliceState {
    Start,
    SentInitial,
    Established,
}

/// High-level state for Bob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BobState {
    Ready,
    ReceivedInitial,
    Established,
}