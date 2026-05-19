# verified_x3dh

`verified_x3dh` is a verification-friendly Rust model of the X3DH handshake core, structured so that selected functions and properties can be extracted with `hax` and checked in the F* backend.

The crate is intentionally split into:

- pure protocol data and state
- deterministic transcript and KDF logic
- proof-facing properties with `hax_lib` annotations
- tests that validate the executable model

It does not try to model full concrete crypto execution in the core. The Rust code is aimed at deterministic protocol reasoning first, with extraction to F* for proof-oriented checking.

## Verification Workflow

This crate now includes two helper scripts:

- `install_x3dh_verification.sh`
- `verify_x3dh`

The intended flow is:

```bash
cd verified_x3dh
./install_x3dh_verification.sh configure --hax-root /absolute/path/to/hax
./install_x3dh_verification.sh check
./install_x3dh_verification.sh install
./install_x3dh_verification.sh run all verify-all
```

Before extraction/verification, you can also run the executable Rust model tests directly:

```bash
cargo test
```

This is a smoke test for the Rust crate, not a substitute for hax/F* verification.

You can also run the abstract handshake demo:

```bash
cargo run --example demo_core_handshake
```

This example exercises the verification-friendly core model and state machine using deterministic demo inputs. It is a runnable model demo, not a real cryptographic X3DH implementation.

`verify_x3dh` will, before any `cargo hax ... fstar` extraction mode:

- ensure `proofs/fstar/extraction/` exists
- fetch `proofs/fstar/extraction/Makefile` if it is missing
- add `hax-lib` under `cfg(hax)` if the crate does not already contain it

This mirrors the generic hax F* quick-start setup (Source: https://hax.cryspen.com/manual/fstar/quick_start/) while keeping the flow crate-local.

Two verification styles are supported:

1. Direct `fstar.exe` verification
   - used by modes like `verify-all`, `verify-kdf`, `verify-properties`
   - requires explicit F* include paths from `HAX_ROOT`
2. Makefile-based hax quick-start verification
   - `verify-make-lax`
   - `verify-make`
   - `verify-make-all`
   - runs `OTHERFLAGS="--lax" make` and/or `make` inside `proofs/fstar/extraction`

The direct `fstar.exe` path still needs these hax-side F* include roots:

- `$HAX_ROOT/proof-libs/fstar/core`
- `$HAX_ROOT/proof-libs/fstar/rust_primitives`
- `$HAX_ROOT/hax-lib/proofs/fstar/extraction`

By contrast, the Makefile-based flow delegates that setup to the Makefile itself.

## Structure

```text
verified_x3dh/
  src/
    lib.rs
    types.rs
    transcript.rs
    kdf.rs
    ad.rs
    handshake_core.rs
    state.rs
    properties.rs
    crypto_adapter.rs
    test_helpers.rs
    tests.rs
  Cargo.toml
  verify_x3dh
  install_x3dh_verification.sh
  INSTALL.md
```

## Files

### `src/lib.rs`

Purpose:

- declares the main modules of the verification core
- exposes the crate structure used by extraction

### `src/types.rs`

Purpose:

- defines verification-friendly core types
- encodes protocol messages, key wrappers, identifiers, and errors
- keeps protocol data explicit and role-specific

Examples:

- `X25519PublicKey`
- `DhOutput`
- `SharedSecret`
- `SignedPreKeyId`
- `OneTimePreKeyId`
- `AliceDhInputs`
- `BobDhInputs`
- `BobLocalState`
- `AliceInitialMessage`

Proof relevance:

- provides the typed surface used by all extracted properties
- includes refined ID wrappers used by hax

### `src/transcript.rs`

Purpose:

- assembles X3DH transcript / KM bytes from already-computed DH outputs
- keeps transcript assembly separate from cryptographic implementation
- provides deterministic, position-based transcript logic for Alice and Bob

Main functions:

- `ordered_from_alice`
- `ordered_from_bob`
- `expected_km_len`
- `is_valid_km_len`
- `assemble_km_from_alice_inputs`
- `assemble_km_from_bob_inputs`

Proof relevance:

- proof target for transcript length and transcript equality properties
- supports the lemma that matching DH inputs produce the same `KM`

### `src/kdf.rs`

Purpose:

- models HKDF-Extract, HKDF-Expand, and the X3DH KDF
- keeps the KDF layer verification-friendly by abstracting concrete HMAC behavior
- provides deterministic output and length reasoning

Main functions:

- `is_valid_hkdf_output_len`
- `is_hash_len`
- `build_x3dh_ikm`
- `hkdf_extract`
- `hkdf_expand`
- `x3dh_kdf`
- `x3dh_kdf_default`

Proof relevance:

- proof target for HKDF output length properties
- proof target for X3DH shared-secret derivation determinism
- supports lemmas of the form same `KM` + same `info` implies same `SK`

Note:

- `hmac_sha256` is abstract in this model, so this layer is about protocol/KDF structure, not cryptographic soundness of HMAC-SHA256 itself

### `src/ad.rs`

Purpose:

- defines associated-data construction for the X3DH core
- implements `AD = Encode(IK_A) || Encode(IK_B)`

Main functions:

- `has_valid_curve_tag`
- `is_valid_ad`
- `encode_x25519_public_key`
- `compute_ad`

Proof relevance:

- supports identity-binding properties
- proof target for the lemma that same identity keys imply same associated data

### `src/handshake_core.rs`

Purpose:

- implements the pure Alice/Bob handshake logic over abstract inputs
- assumes DH outputs, signature validity, plaintext/ciphertext, and nonce are already available
- keeps the core free of randomness, AEAD execution, and concrete DH operations

Main functions:

- `alice_initiate_core`
- `bob_receive_core`

Main input types:

- `AliceInitiateCoreInputs`
- `BobReceiveCoreInputs`

Proof relevance:

- proof target for agreement at the pure-core level
- supports lemmas relating matching core inputs to matching shared secrets and associated data

### `src/state.rs`

Purpose:

- models explicit protocol phases and state transitions
- captures invalid-transition rejection and OPK consumption behavior

State types:

- `AliceProtocolState`
- `BobProtocolState`

Main transition functions:

- `alice_start`
- `alice_establish`
- `bob_receive`
- `bob_establish`

Proof relevance:

- proof target for “no invalid transition” style properties
- supports protocol-state agreement properties built on top of the pure core

### `src/properties.rs`

Purpose:

- central proof-facing layer for hax/F*
- defines executable predicates and extraction-friendly lemmas
- composes transcript, KDF, AD, handshake core, and state properties

This is the main place where `#[hax_lib::requires]`, `#[hax_lib::ensures]`, and `#[hax_lib::include]` are used.

### `src/crypto_adapter.rs`

Purpose:

- placeholder for future concrete crypto integration
- not currently part of the proof-focused core

### `src/test_helpers.rs`

Purpose:

- deterministic test fixtures and small constructors used by unit and integration tests

### `src/tests.rs`

Purpose:

- cross-module integration-style tests for the executable model
- validates end-to-end agreement behavior for the pure Rust core

## F* Lemmas / Proof Targets

The following items are the main proof-facing extraction targets currently represented in the crate.

### Transcript-level

- `verified_x3dh::transcript::assemble_km_from_alice_inputs`
- `verified_x3dh::transcript::assemble_km_from_bob_inputs`

Expected proof shape:

- assembled `KM` has the correct length
- matching positional DH inputs produce identical `KM`

### KDF-level

- `verified_x3dh::kdf::hkdf_extract`
- `verified_x3dh::kdf::hkdf_expand`
- `verified_x3dh::kdf::x3dh_kdf`

Expected proof shape:

- HKDF extract returns a hash-length pseudorandom key
- successful HKDF expand returns exactly the requested length
- X3DH KDF returns a 32-byte shared secret
- same `KM` and same `info` imply same derived `SK`

### Associated-data level

- `verified_x3dh::ad::encode_x25519_public_key`
- `verified_x3dh::ad::compute_ad`

Expected proof shape:

- encoded public keys have the correct format/length
- same identity keys imply same associated data

### Handshake-core level

- `verified_x3dh::handshake_core::alice_initiate_core`
- `verified_x3dh::handshake_core::bob_receive_core`

Expected proof shape:

- matching core inputs imply matching shared secrets
- matching core inputs imply matching associated data
- matching core inputs imply matching pure-core session outputs

### State-machine level

- `verified_x3dh::state::alice_start`
- `verified_x3dh::state::alice_establish`
- `verified_x3dh::state::bob_receive`
- `verified_x3dh::state::bob_establish`

Expected proof shape:

- invalid transitions are rejected
- OPK consumption is reflected in Bob’s state transition behavior
- established Alice/Bob states agree when started from matching inputs

## Proof-Facing Properties In `properties.rs`

The main extraction-friendly predicates and lemmas currently include:

- `dh_inputs_match`
- `core_inputs_match_for_shared_secret`
- `core_inputs_match_for_ad`
- `prop_matching_dh_inputs_produce_same_km`
- `prop_same_km_implies_same_sk`
- `prop_equal_km_values_imply_equal_sk`
- `prop_same_identity_keys_imply_same_ad`
- `prop_matching_dh_inputs_imply_same_sk`
- `prop_matching_core_inputs_imply_same_shared_secret`
- `prop_matching_core_inputs_imply_same_ad`
- `prop_matching_core_inputs_imply_same_session_outputs`
- `established_states_agree`
- `prop_established_states_agree_from_matching_inputs`

The state module also contributes proof-facing transition properties:

- `prop_alice_start_rejects_non_start`
- `prop_alice_establish_rejects_without_sent_initial`
- `prop_bob_receive_rejects_non_ready`
- `prop_bob_establish_rejects_without_received_initial`
- `prop_bob_receive_consumes_opk_when_referenced`

## Extraction

Sanity-check frontend extraction:

```bash
cargo hax json
```

Full F* extraction:

```bash
cargo hax into fstar
```

Examples of partial extraction:

```bash
cargo hax into -i "-** +verified_x3dh::transcript::*" fstar
cargo hax into -i "-** +verified_x3dh::kdf::*" fstar
cargo hax into -i "-** +verified_x3dh::properties::*" fstar
```

Or use the provided runner:

```bash
./verify_x3dh all verify-all
./verify_x3dh kdf verify-kdf
./verify_x3dh properties verify-properties
./verify_x3dh verify-only verify-make-lax
./verify_x3dh all verify-make-all
```

The installer wrapper exposes the same flow:

```bash
./install_x3dh_verification.sh run all verify-all
./install_x3dh_verification.sh run all verify-make-all
```

## Verification Scope

What this crate currently aims to verify:

- deterministic transcript assembly
- explicit state transitions
- agreement-style properties over the pure core
- no invalid transition behavior in the modeled state machine
- F* extraction compatibility for proof-facing items

What this crate does not currently prove:

- concrete cryptographic security of X25519, Ed25519, HKDF, or AEAD
- adversarial network security
- symbolic or computational X3DH security as a full protocol proof
- PQXDH behavior

## Notes

- `kdf_old.rs` and `kdf_old2.rs` are older variants kept in the tree; `kdf.rs` is the active KDF model.
- `crypto_adapter.rs` is currently a placeholder and not the focus of extraction.
- the proof surface has been tightened to prefer stable equality/agreement properties over unjustified “different inputs imply different secrets” claims.
- for installation and environment setup, see `INSTALL.md`.
