# verified_x3dh

`verified_x3dh` is a verification-friendly Rust model of the X3DH handshake core. It is structured so selected functions and properties can be extracted with `hax` and checked in the F* backend.

This crate focuses on deterministic protocol reasoning, not concrete cryptographic execution. The core keeps DH outputs, signature checks, AEAD inputs, and randomness abstract, then proves protocol-level structure and agreement properties over those abstract values.

## What It Contains

- typed protocol data and message/state structures
- deterministic transcript and KDF assembly
- pure Alice/Bob handshake-core logic
- explicit state-machine transitions
- proof-facing properties with `hax_lib` annotations
- executable Rust tests for local invariants and cross-module scenarios

The current test layout uses both:

- inline `#[cfg(test)]` unit tests inside source files for module-local invariants
- `src/tests.rs` for broader cross-module executable-model tests

## Quick Start

Run the Rust model:

```bash
cargo test
cargo run --example demo_core_handshake
```

Run the verification flow:

```bash
cd verified_x3dh
./install_x3dh_verification.sh configure \
  --hax-root /absolute/path/to/hax \
  --extraction-dir "$PWD/proofs/fstar/extraction"
./install_x3dh_verification.sh check
./install_x3dh_verification.sh install
./install_x3dh_verification.sh run all verify-all
```

For installation details, environment variables, and verification modes, see [INSTALL.md](INSTALL.md).

## Module Map

- `src/types.rs`: core types, identifiers, message structs, local Bob state, errors
- `src/transcript.rs`: deterministic X3DH transcript / KM assembly from ordered DH outputs
- `src/kdf.rs`: HKDF model and X3DH KDF over assembled key material
- `src/ad.rs`: associated-data construction `Encode(IK_A) || Encode(IK_B)`
- `src/handshake_core.rs`: pure Alice/Bob handshake logic over abstract inputs
- `src/state.rs`: explicit protocol phases and transition rules
- `src/properties.rs`: proof-facing predicates and agreement lemmas
- `src/test_helpers.rs`: deterministic fixtures for tests
- `src/tests.rs`: cross-module executable-model tests
- `src/crypto_adapter.rs`: placeholder for later concrete crypto integration

## Current Verification Surface

The active proof surface is centered on:

- transcript correctness:
  - matching positional DH inputs produce the same `KM`
  - `KM` length is valid for OPK-present and OPK-absent cases
- KDF correctness:
  - HKDF output lengths are constrained correctly
  - same `KM` and same `info` imply same derived `SK`
- associated-data correctness:
  - same identity keys imply same `AD`
- pure-core agreement:
  - matching Alice/Bob core inputs imply matching shared secrets and associated data
- state-machine correctness:
  - invalid transitions are rejected
  - Bob consumes OPK only when referenced
  - OPK consumption is at-most-once in the modeled in-memory state machine
  - Bob preserves identity key, signing key, and signed prekey across successful receive
  - `bob_establish` does not restore a consumed OPK

## Current Scope

What this crate currently aims to verify:

- deterministic transcript assembly
- explicit state transitions
- agreement-style properties over the pure X3DH core
- local OPK/state-safety invariants in the Bob state machine
- extraction compatibility for proof-facing items

What this crate does not currently prove:

- concrete security of X25519, Ed25519, HKDF, or AEAD
- adversarial network security
- symbolic or computational security of full X3DH
- persistence/reload-style replay safety beyond the current in-memory state machine
- PQXDH behavior

## Notes

- `Cargo.toml` uses the published `hax-lib` dependency; machine-local `hax` paths are handled by the helper scripts, not the manifest.
- The active modules currently build and test cleanly with `cargo test`.
- The next protocol extension is PQXDH, but the current X3DH/state baseline should remain stable while that work is added in parallel rather than overloaded into the existing classical path.
