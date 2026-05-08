from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import hashlib
import hmac
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ============================================================================
# X3DH parameters
# ============================================================================
#
# This module demonstrates an X3DH-style key agreement flow using:
#   - X25519 for Diffie-Hellman
#   - Ed25519 for signed-prekey authentication in this demo
#   - HKDF with HMAC-SHA256 for shared-secret derivation
#   - ChaCha20-Poly1305 for encrypting the initial message
#
# Per the X3DH specification, the shared secret is derived from:
#   SK = HKDF(
#       salt = zero bytes of hash length,
#       IKM  = F || KM,
#       info = application-specific ASCII string
#   )
#
# For X25519:
#   F = 32 bytes of 0xFF
#
# Notes:
#   - This demo uses Ed25519 as a practical stand-in for XEdDSA signing.
#   - That is suitable for learning, but it is not exact Signal-compatible
#     X3DH interoperability.
# ============================================================================

HASH_LEN = 32
F_25519 = b"\xff" * 32
DEFAULT_INFO = b"MyApp_X3DH_X25519_SHA256"

# Application-defined single-byte curve tag for Encode(PK).
CURVE_TAG_X25519 = b"\x05"

# ChaCha20-Poly1305 parameters.
AEAD_KEY_LEN = 32
AEAD_NONCE_LEN = 12


# ============================================================================
# HKDF helpers
# ============================================================================

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract using HMAC-SHA256.

    Derives a pseudorandom key (PRK) from input key material.

    RFC 5869:
        PRK = HMAC(salt, IKM)

    @param salt Optional salt value used as the HMAC key.
    @param ikm  Input key material (raw secret bytes).
    @return     Pseudorandom key (PRK).
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand using HMAC-SHA256.

    Generates output keying material (OKM) from a pseudorandom key (PRK).

    RFC 5869:
        OKM = HKDF-Expand(PRK, info, length)

    HKDF-Expand produces output in blocks. For SHA-256, each block is 32 bytes.

    The N-th block is computed as:
        T(N) = HMAC(PRK, T(N-1) || info || 0x0N)

    where:
        T(0) = empty string

    @param prk    Pseudorandom key (PRK), typically from HKDF-Extract.
    @param info   Optional context and application-specific information.
    @param length Number of output bytes to generate.
    @return       Output keying material (OKM).
    @raises ValueError If length is not positive.
    @raises ValueError If length exceeds the HKDF limit for SHA-256.
    """
    if length <= 0:
        raise ValueError("length must be positive")
    if length > 255 * HASH_LEN:
        raise ValueError("length too large for HKDF-Expand with SHA-256")

    okm = bytearray()
    previous = b""
    counter = 1

    while len(okm) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        okm.extend(previous)
        counter += 1

    return bytes(okm[:length])


def x3dh_kdf(km: bytes, info: bytes = DEFAULT_INFO) -> bytes:
    """
    X3DH shared-secret derivation for X25519 + SHA-256.

    Derives the final shared secret (SK) using the X3DH-specific HKDF input
    construction.

    Per the X3DH specification:
        SK = HKDF(
            salt = 32 zero bytes,
            IKM  = F || KM,
            info = application-specific context string
        )

    For X25519:
        F = 32 bytes of 0xFF

    This function derives 32 bytes, matching the SHA-256-based shared secret
    size used in this demo.

    @param km   Input key material (KM), the concatenated DH outputs.
    @param info Application-specific context string used to bind the derived
                key to a protocol or application.
    @return     Final X3DH shared secret (SK).
    """
    zero_salt = b"\x00" * HASH_LEN
    prk = hkdf_extract(zero_salt, F_25519 + km)
    return hkdf_expand(prk, info, 32)


# ============================================================================
# Serialization helpers
# ============================================================================

def public_bytes_x25519(pub: x25519.X25519PublicKey) -> bytes:
    """
    Return the raw 32-byte X25519 public key encoding.

    Converts an X25519 public key object into its raw byte form.

    Raw bytes are needed because cryptographic libraries represent keys as
    objects, while protocols require byte sequences for:
        - sending over the network
        - storing in bundles
        - comparing or serializing

    For X25519 public keys, the raw encoding is always 32 bytes.

    @param pub X25519 public key object.
    @return    Raw 32-byte public key encoding.
    """
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def private_bytes_x25519(priv: x25519.X25519PrivateKey) -> bytes:
    """
    Return the raw 32-byte X25519 private key encoding.

    Converts an X25519 private key object into its raw byte representation.

    Raw bytes are useful for:
        - saving the key
        - restoring it later
        - debugging
        - exporting or importing keys

    For X25519 private keys, the raw encoding is always 32 bytes.

    @param priv X25519 private key object.
    @return     Raw 32-byte private key encoding.
    """
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_bytes_ed25519(pub: ed25519.Ed25519PublicKey) -> bytes:
    """
    Return the raw 32-byte Ed25519 public key encoding.

    Converts an Ed25519 public key object into its raw byte form.

    @param pub Ed25519 public key object.
    @return    Raw 32-byte public key encoding.
    """
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def encode_x25519_public_key(pub: x25519.X25519PublicKey) -> bytes:
    """
    Encode an X25519 public key in application-defined X3DH format.

    The X3DH specification requires an Encode(PK) function and recommends
    including a curve or type identifier before the public key bytes.

    This demo encodes a public key as:
        curve_tag || raw_x25519_public_key

    where:
        curve_tag = 0x05 for X25519 in this application-defined format

    @param pub X25519 public key to encode.
    @return    Encoded public key bytes.
    """
    return CURVE_TAG_X25519 + public_bytes_x25519(pub)


def dh(
    priv: x25519.X25519PrivateKey,
    pub: x25519.X25519PublicKey,
) -> bytes:
    """
    Perform one X25519 Diffie-Hellman operation.

    Computes the shared secret produced by combining a private X25519 key
    with a peer public X25519 key.

    @param priv Local X25519 private key.
    @param pub  Peer X25519 public key.
    @return     Raw 32-byte Diffie-Hellman shared secret.
    """
    return priv.exchange(pub)


# ============================================================================
# AEAD helpers
# ============================================================================

def aead_encrypt(
    sk: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using ChaCha20-Poly1305.

    In this demo, the X3DH shared secret (SK) is used directly as the AEAD key.

    @param sk              32-byte AEAD key.
    @param plaintext       Plaintext to encrypt.
    @param associated_data Additional authenticated data (AD).
    @return                Tuple of (nonce, ciphertext).
    @raises ValueError If the AEAD key length is invalid.
    """
    if len(sk) != AEAD_KEY_LEN:
        raise ValueError(f"AEAD key must be {AEAD_KEY_LEN} bytes")
    nonce = secrets.token_bytes(AEAD_NONCE_LEN)
    cipher = ChaCha20Poly1305(sk)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aead_decrypt(
    sk: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
) -> bytes:
    """
    Decrypt ciphertext using ChaCha20-Poly1305.

    @param sk              32-byte AEAD key.
    @param nonce           12-byte ChaCha20-Poly1305 nonce.
    @param ciphertext      Ciphertext including authentication tag.
    @param associated_data Additional authenticated data (AD).
    @return                Decrypted plaintext.
    @raises ValueError If the AEAD key length is invalid.
    """
    if len(sk) != AEAD_KEY_LEN:
        raise ValueError(f"AEAD key must be {AEAD_KEY_LEN} bytes")
    cipher = ChaCha20Poly1305(sk)
    return cipher.decrypt(nonce, ciphertext, associated_data)


# ============================================================================
# Key types
# ============================================================================

@dataclass(frozen=True)
class IdentityKeyPair:
    """
    Long-term X25519 identity key pair used for Diffie-Hellman.

    This key pair represents a party's stable X25519 identity key in the X3DH
    flow.

    @param private_key Private X25519 identity key.
    @param public_key  Public X25519 identity key.
    """
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        """
        Generate a new X25519 identity key pair.

        @return Newly generated identity key pair.
        """
        priv = x25519.X25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())


@dataclass(frozen=True)
class IdentitySigningKeyPair:
    """
    Long-term Ed25519 signing key pair.

    This demo uses Ed25519 to sign Bob's signed prekey as a practical stand-in
    for the XEdDSA-based identity signing model used in the X3DH
    specification.

    @param private_key Private Ed25519 signing key.
    @param public_key  Public Ed25519 verification key.
    """
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "IdentitySigningKeyPair":
        """
        Generate a new Ed25519 signing key pair.

        @return Newly generated signing key pair.
        """
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())


@dataclass(frozen=True)
class SignedPreKeyPair:
    """
    Medium-term signed prekey pair.

    A signed prekey is an X25519 key pair whose public key is signed by the
    party's long-term signing key.

    @param key_id      Application-defined identifier for this signed prekey.
    @param private_key Private X25519 signed prekey.
    @param public_key  Public X25519 signed prekey.
    @param signature   Signature over Encode(SPK).
    """
    key_id: int
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey
    signature: bytes

    @classmethod
    def generate(
        cls,
        key_id: int,
        signer: IdentitySigningKeyPair,
    ) -> "SignedPreKeyPair":
        """
        Generate and sign a new signed prekey pair.

        The public signed prekey is signed over its encoded form.

        @param key_id Application-defined signed prekey identifier.
        @param signer Long-term signing key used to sign the prekey.
        @return       Newly generated signed prekey pair.
        """
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        encoded_spk = encode_x25519_public_key(pub)
        signature = signer.private_key.sign(encoded_spk)
        return cls(
            key_id=key_id,
            private_key=priv,
            public_key=pub,
            signature=signature,
        )


@dataclass(frozen=True)
class OneTimePreKeyPair:
    """
    Optional one-time prekey pair.

    A one-time prekey may be consumed during one X3DH initiation to add an
    extra Diffie-Hellman component.

    @param key_id      Application-defined identifier for this one-time prekey.
    @param private_key Private X25519 one-time prekey.
    @param public_key  Public X25519 one-time prekey.
    """
    key_id: int
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls, key_id: int) -> "OneTimePreKeyPair":
        """
        Generate a new one-time prekey pair.

        @param key_id Application-defined one-time prekey identifier.
        @return       Newly generated one-time prekey pair.
        """
        priv = x25519.X25519PrivateKey.generate()
        return cls(key_id=key_id, private_key=priv, public_key=priv.public_key())


@dataclass(frozen=True)
class BobPreKeyBundle:
    """
    Prekey bundle published by Bob and fetched by Alice.

    This bundle contains the public material Alice needs to begin the X3DH
    handshake.

    @param identity_key          Bob's public X25519 identity key.
    @param signing_key           Bob's public Ed25519 signing key.
    @param signed_prekey_id      Identifier for Bob's signed prekey.
    @param signed_prekey         Bob's public signed prekey.
    @param signed_prekey_signature Signature over Encode(SPK_B).
    @param one_time_prekey_id    Identifier for the optional one-time prekey.
    @param one_time_prekey       Optional public one-time prekey.
    """
    identity_key: x25519.X25519PublicKey
    signing_key: ed25519.Ed25519PublicKey
    signed_prekey_id: int
    signed_prekey: x25519.X25519PublicKey
    signed_prekey_signature: bytes
    one_time_prekey_id: Optional[int] = None
    one_time_prekey: Optional[x25519.X25519PublicKey] = None


@dataclass(frozen=True)
class AliceInitialMessage:
    """
    Alice's first encrypted message to Bob.

    Per the X3DH flow, this message carries:
        - Alice's identity key
        - Alice's ephemeral key
        - identifiers for Bob's selected prekeys
        - the AEAD nonce
        - the initial ciphertext

    @param alice_identity_key  Alice's public X25519 identity key.
    @param alice_ephemeral_key Alice's public X25519 ephemeral key.
    @param signed_prekey_id    Identifier of Bob's signed prekey used.
    @param one_time_prekey_id  Identifier of Bob's one-time prekey used, if any.
    @param nonce               AEAD nonce.
    @param ciphertext          Encrypted initial payload.
    """
    alice_identity_key: x25519.X25519PublicKey
    alice_ephemeral_key: x25519.X25519PublicKey
    signed_prekey_id: int
    one_time_prekey_id: Optional[int]
    nonce: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class AliceHandshakeResult:
    """
    Result of Alice's X3DH initiation step.

    @param initial_message Alice's initial message to Bob.
    @param shared_secret   Derived shared secret.
    @param associated_data Associated data used by AEAD.
    """
    initial_message: AliceInitialMessage
    shared_secret: bytes
    associated_data: bytes


@dataclass(frozen=True)
class BobHandshakeResult:
    """
    Result of Bob processing Alice's initial message.

    @param shared_secret   Reconstructed shared secret.
    @param associated_data Associated data used by AEAD.
    @param plaintext       Decrypted initial payload.
    """
    shared_secret: bytes
    associated_data: bytes
    plaintext: bytes


# ============================================================================
# Signature verification
# ============================================================================

def verify_signed_prekey_or_raise(
    signing_public_key: ed25519.Ed25519PublicKey,
    signed_prekey_public_key: x25519.X25519PublicKey,
    signature: bytes,
) -> None:
    """
    Verify Bob's signed prekey signature.

    X3DH requires Alice to authenticate Bob's signed prekey before using it.
    In this demo, an Ed25519 signature is verified over Encode(SPK_B).

    @param signing_public_key     Public key used to verify the signature.
    @param signed_prekey_public_key Public signed prekey being authenticated.
    @param signature              Signature over Encode(SPK_B).
    @raises ValueError If signature verification fails.
    """
    message = encode_x25519_public_key(signed_prekey_public_key)
    try:
        signing_public_key.verify(signature, message)
    except InvalidSignature as e:
        raise ValueError("Bob signed prekey signature verification failed") from e


# ============================================================================
# Associated data
# ============================================================================

def compute_ad(
    alice_identity_key: x25519.X25519PublicKey,
    bob_identity_key: x25519.X25519PublicKey,
) -> bytes:
    """
    Compute associated data (AD) for the initial AEAD message.

    In this demo:
        AD = Encode(IK_A) || Encode(IK_B)

    @param alice_identity_key Alice's public identity key.
    @param bob_identity_key   Bob's public identity key.
    @return                   Associated data bytes.
    """
    return encode_x25519_public_key(alice_identity_key) + encode_x25519_public_key(bob_identity_key)


# ============================================================================
# Alice side
# ============================================================================

def alice_initiate_x3dh(
    alice_identity: IdentityKeyPair,
    bob_bundle: BobPreKeyBundle,
    initial_plaintext: bytes,
    info: bytes = DEFAULT_INFO,
) -> AliceHandshakeResult:
    """
    Perform Alice's side of the X3DH initiation flow.

    Steps:
        1. Verify Bob's signed prekey signature.
        2. Generate Alice's ephemeral key pair.
        3. Compute:
               DH1 = DH(IK_A, SPK_B)
               DH2 = DH(EK_A, IK_B)
               DH3 = DH(EK_A, SPK_B)
               DH4 = DH(EK_A, OPK_B)   if present
        4. Concatenate the DH outputs into KM.
        5. Derive:
               SK = KDF(KM)
        6. Compute:
               AD = Encode(IK_A) || Encode(IK_B)
        7. Encrypt the initial payload with AEAD using SK and AD.
        8. Return Alice's initial message and handshake result.

    @param alice_identity   Alice's long-term identity key pair.
    @param bob_bundle       Bob's published prekey bundle.
    @param initial_plaintext Initial plaintext payload to encrypt.
    @param info             Application-specific HKDF info string.
    @return                 Alice's handshake result.
    @raises ValueError If Bob's signed prekey signature is invalid.
    """
    verify_signed_prekey_or_raise(
        signing_public_key=bob_bundle.signing_key,
        signed_prekey_public_key=bob_bundle.signed_prekey,
        signature=bob_bundle.signed_prekey_signature,
    )

    ek_a_priv = x25519.X25519PrivateKey.generate()
    ek_a_pub = ek_a_priv.public_key()

    dh1 = dh(alice_identity.private_key, bob_bundle.signed_prekey)
    dh2 = dh(ek_a_priv, bob_bundle.identity_key)
    dh3 = dh(ek_a_priv, bob_bundle.signed_prekey)

    km = bytearray()
    km.extend(dh1)
    km.extend(dh2)
    km.extend(dh3)

    if bob_bundle.one_time_prekey is not None:
        dh4 = dh(ek_a_priv, bob_bundle.one_time_prekey)
        km.extend(dh4)

    sk = x3dh_kdf(bytes(km), info=info)
    ad = compute_ad(alice_identity.public_key, bob_bundle.identity_key)

    nonce, ciphertext = aead_encrypt(sk, initial_plaintext, ad)

    del dh1, dh2, dh3, km
    if bob_bundle.one_time_prekey is not None:
        del dh4

    initial_message = AliceInitialMessage(
        alice_identity_key=alice_identity.public_key,
        alice_ephemeral_key=ek_a_pub,
        signed_prekey_id=bob_bundle.signed_prekey_id,
        one_time_prekey_id=bob_bundle.one_time_prekey_id,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    return AliceHandshakeResult(
        initial_message=initial_message,
        shared_secret=sk,
        associated_data=ad,
    )


# ============================================================================
# Bob-side key store
# ============================================================================

@dataclass
class BobLocalState:
    """
    Bob's local private state and prekey store.

    In a real implementation, these keys would typically be stored
    persistently and indexed by key identifier.

    @param identity_key     Bob's long-term X25519 identity key pair.
    @param signing_key      Bob's long-term signing key pair.
    @param signed_prekeys   Mapping of signed prekey id to signed prekey pair.
    @param one_time_prekeys Mapping of one-time prekey id to one-time prekey pair.
    """
    identity_key: IdentityKeyPair
    signing_key: IdentitySigningKeyPair
    signed_prekeys: dict[int, SignedPreKeyPair]
    one_time_prekeys: dict[int, OneTimePreKeyPair]

    def build_prekey_bundle(
        self,
        signed_prekey_id: int,
        use_one_time_prekey: bool = True,
    ) -> BobPreKeyBundle:
        """
        Build a public prekey bundle for Alice.

        Optionally includes one available one-time prekey.

        @param signed_prekey_id     Identifier of the signed prekey to publish.
        @param use_one_time_prekey  Whether to include one available one-time prekey.
        @return                     Bob's public prekey bundle.
        @raises KeyError If the signed prekey id is unknown.
        """
        if signed_prekey_id not in self.signed_prekeys:
            raise KeyError(f"Unknown signed prekey id {signed_prekey_id}")

        spk = self.signed_prekeys[signed_prekey_id]

        opk_id: Optional[int] = None
        opk_pub: Optional[x25519.X25519PublicKey] = None

        if use_one_time_prekey and self.one_time_prekeys:
            opk_id = next(iter(self.one_time_prekeys))
            opk_pub = self.one_time_prekeys[opk_id].public_key

        return BobPreKeyBundle(
            identity_key=self.identity_key.public_key,
            signing_key=self.signing_key.public_key,
            signed_prekey_id=spk.key_id,
            signed_prekey=spk.public_key,
            signed_prekey_signature=spk.signature,
            one_time_prekey_id=opk_id,
            one_time_prekey=opk_pub,
        )


# ============================================================================
# Bob side
# ============================================================================

def bob_receive_x3dh(
    bob_state: BobLocalState,
    alice_message: AliceInitialMessage,
    info: bytes = DEFAULT_INFO,
) -> BobHandshakeResult:
    """
    Perform Bob's side of the X3DH receive flow.

    Bob reconstructs the shared secret using the referenced prekeys and
    decrypts Alice's initial ciphertext.

    Steps:
        1. Load the referenced signed prekey.
        2. Load the referenced one-time prekey, if any.
        3. Compute:
               DH1 = DH(SPK_B, IK_A)
               DH2 = DH(IK_B, EK_A)
               DH3 = DH(SPK_B, EK_A)
               DH4 = DH(OPK_B, EK_A)   if used
        4. Concatenate the DH outputs into KM.
        5. Derive:
               SK = KDF(KM)
        6. Compute:
               AD = Encode(IK_A) || Encode(IK_B)
        7. Decrypt the ciphertext using SK and AD.
        8. If an OPK was used, remove it from the local store.

    @param bob_state      Bob's local key state and prekey store.
    @param alice_message  Alice's initial X3DH message.
    @param info           Application-specific HKDF info string.
    @return               Bob's handshake result.
    @raises ValueError If the referenced signed prekey is not found.
    @raises ValueError If the referenced one-time prekey is not found.
    """
    spk = bob_state.signed_prekeys.get(alice_message.signed_prekey_id)
    if spk is None:
        raise ValueError("Referenced signed prekey id not found")

    opk: Optional[OneTimePreKeyPair] = None
    if alice_message.one_time_prekey_id is not None:
        opk = bob_state.one_time_prekeys.get(alice_message.one_time_prekey_id)
        if opk is None:
            raise ValueError("Referenced one-time prekey id not found")

    dh1 = dh(spk.private_key, alice_message.alice_identity_key)
    dh2 = dh(bob_state.identity_key.private_key, alice_message.alice_ephemeral_key)
    dh3 = dh(spk.private_key, alice_message.alice_ephemeral_key)

    km = bytearray()
    km.extend(dh1)
    km.extend(dh2)
    km.extend(dh3)

    if opk is not None:
        dh4 = dh(opk.private_key, alice_message.alice_ephemeral_key)
        km.extend(dh4)

    sk = x3dh_kdf(bytes(km), info=info)
    ad = compute_ad(alice_message.alice_identity_key, bob_state.identity_key.public_key)

    plaintext = aead_decrypt(
        sk,
        alice_message.nonce,
        alice_message.ciphertext,
        ad,
    )

    del dh1, dh2, dh3, km
    if opk is not None:
        del dh4
        bob_state.one_time_prekeys.pop(opk.key_id, None)

    return BobHandshakeResult(
        shared_secret=sk,
        associated_data=ad,
        plaintext=plaintext,
    )


# ============================================================================
# Demo
# ============================================================================

def demo() -> None:
    """
    Run an end-to-end X3DH-style handshake demo.

    This function:
        - creates Bob's identity, signing, signed-prekey, and one-time prekeys
        - creates Alice's identity key
        - builds Bob's public prekey bundle
        - lets Alice derive a shared secret and encrypt an initial payload
        - lets Bob derive the same shared secret and decrypt the payload

    @return None.
    """
    bob_identity = IdentityKeyPair.generate()
    bob_signing = IdentitySigningKeyPair.generate()

    bob_spk = SignedPreKeyPair.generate(key_id=1001, signer=bob_signing)
    bob_opk_1 = OneTimePreKeyPair.generate(key_id=2001)
    bob_opk_2 = OneTimePreKeyPair.generate(key_id=2002)

    bob_state = BobLocalState(
        identity_key=bob_identity,
        signing_key=bob_signing,
        signed_prekeys={bob_spk.key_id: bob_spk},
        one_time_prekeys={
            bob_opk_1.key_id: bob_opk_1,
            bob_opk_2.key_id: bob_opk_2,
        },
    )

    alice_identity = IdentityKeyPair.generate()

    bundle = bob_state.build_prekey_bundle(signed_prekey_id=1001, use_one_time_prekey=True)

    initial_payload = json.dumps(
        {
            "type": "initial-message",
            "body": "Hello Bob, this is Alice.",
        }
    ).encode("utf-8")

    alice_result = alice_initiate_x3dh(
        alice_identity=alice_identity,
        bob_bundle=bundle,
        initial_plaintext=initial_payload,
    )

    bob_result = bob_receive_x3dh(
        bob_state=bob_state,
        alice_message=alice_result.initial_message,
    )

    print("Alice SK:", alice_result.shared_secret.hex())
    print("Bob   SK:", bob_result.shared_secret.hex())
    print("Shared secret matches:", alice_result.shared_secret == bob_result.shared_secret)
    print("AD matches:", alice_result.associated_data == bob_result.associated_data)
    print("Decrypted payload:", bob_result.plaintext.decode("utf-8"))
    print("Remaining OPKs after receive:", sorted(bob_state.one_time_prekeys.keys()))


if __name__ == "__main__":
    demo()