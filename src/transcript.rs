//! transcript.rs
//!
//! Transcript / KM assembly for a verification-friendly X3DH core.
//!
//! This module does not perform any cryptographic operations.
//! It only assembles already-computed DH outputs into the byte string
//! that is fed into the X3DH KDF.

use crate::types::{AliceDhInputs, BobDhInputs, DhOutput, X25519_KEY_LEN};

/// Number of mandatory DH outputs in X3DH KM assembly.
pub const BASE_DH_COUNT: usize = 3;

/// Number of DH outputs when an OPK is present.
pub const EXTENDED_DH_COUNT: usize = 4;

/// X3DH KM length without OPK.
pub const KM_LEN_WITHOUT_OPK: usize = BASE_DH_COUNT * X25519_KEY_LEN;

/// X3DH KM length with OPK.
pub const KM_LEN_WITH_OPK: usize = EXTENDED_DH_COUNT * X25519_KEY_LEN;

/// Transcript / KM bytes.
///
/// This wrapper prevents accidental confusion with other byte strings.
#[derive(Clone, Debug, PartialEq, Eq)]
//pub struct KeyMaterial(pub Vec<u8>);
pub enum KeyMaterial {
    //X3dhWithoutOpk([u8; 96]),
    //X3dhWithOpk([u8; 128]),
    WithoutOpk([u8; KM_LEN_WITHOUT_OPK]),
    WithOpk([u8; KM_LEN_WITH_OPK]),
    //PqxdhWithoutOpk([u8; ...]),
    //PqxdhWithOpk([u8; ...]),
}

impl KeyMaterial {
    pub fn len(&self) -> usize {
        match self {
            KeyMaterial::WithoutOpk(_) => KM_LEN_WITHOUT_OPK,
            KeyMaterial::WithOpk(_) => KM_LEN_WITH_OPK,
        }
    }

    pub fn as_vec(&self) -> Vec<u8> {
        match self {
            KeyMaterial::WithoutOpk(km) => km.to_vec(),
            KeyMaterial::WithOpk(km) => km.to_vec(),
        }
    }
}
/// Common positional representation of transcript inputs.
///
/// Alice and Bob use different protocol interpretations for the DH values,
/// but after crypto evaluation they must agree positionally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderedDhInputs {
    pub dh1: DhOutput,
    pub dh2: DhOutput,
    pub dh3: DhOutput,
    pub dh4: Option<DhOutput>,
}

/// Convert Alice-side DH inputs into the common ordered form.
#[hax_lib::ensures(|result|
    result.dh1 == inputs.dh1
        && result.dh2 == inputs.dh2
        && result.dh3 == inputs.dh3
        && result.dh4 == inputs.dh4
)]
pub fn ordered_from_alice(inputs: &AliceDhInputs) -> OrderedDhInputs {
    OrderedDhInputs {
        dh1: inputs.dh1,
        dh2: inputs.dh2,
        dh3: inputs.dh3,
        dh4: inputs.dh4,
    }
}

/// Convert Bob-side DH inputs into the common ordered form.
#[hax_lib::ensures(|result|
    result.dh1 == inputs.dh1
        && result.dh2 == inputs.dh2
        && result.dh3 == inputs.dh3
        && result.dh4 == inputs.dh4
)]
pub fn ordered_from_bob(inputs: &BobDhInputs) -> OrderedDhInputs {
    OrderedDhInputs {
        dh1: inputs.dh1,
        dh2: inputs.dh2,
        dh3: inputs.dh3,
        dh4: inputs.dh4,
    }
}

/// Append a single DH output to a transcript buffer.
/// fn append_dh_output(buf: &mut Vec<u8>, dh: DhOutput) {
///    buf.extend_from_slice(&dh.0);
/// }

/// Build the array directly
/// #[hax_lib::requires(offset + X25519_KEY_LEN <= out.len())]
/// fn copy_dh(out: &mut [u8], offset: usize, dh: DhOutput) {
///    out[offset..offset + X25519_KEY_LEN].copy_from_slice(&dh.0);
/// }


/// Return the expected KM length in bytes for the given presence of OPK.
#[hax_lib::ensures(|result|
    if has_opk {
        result == KM_LEN_WITH_OPK
    } else {
        result == KM_LEN_WITHOUT_OPK
    }
)]
pub fn expected_km_len(has_opk: bool) -> usize {
    if has_opk {
        KM_LEN_WITH_OPK
    } else {
        KM_LEN_WITHOUT_OPK
    }
}

/// Check whether a KM byte string has a valid X3DH length.
#[hax_lib::ensures(|result|
    result == (km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK)
)]
pub fn is_valid_km_len(km: &[u8]) -> bool {
    km.len() == KM_LEN_WITHOUT_OPK || km.len() == KM_LEN_WITH_OPK
}

/// Assemble X3DH input key material (KM) from ordered DH outputs.
///
/// X3DH order:
///  1. DH1
///  2. DH2
///  3. DH3
///  4. Optional DH4
///
/// The caller is responsible for ensuring that these positional values
/// correspond to the protocol's required order.
#[hax_lib::ensures(|result|
    result.len() == expected_km_len(inputs.dh4.is_some())
)]
pub fn assemble_km_from_ordered_inputs(inputs: &OrderedDhInputs) -> KeyMaterial {
    // Earlier versions built a Vec transcript incrementally. The current model
    // writes directly into fixed-size arrays so KM length stays explicit.
    match inputs.dh4 {
        None => {
            let mut km = [0u8; KM_LEN_WITHOUT_OPK];

            km[0..X25519_KEY_LEN].copy_from_slice(&inputs.dh1.0);
            km[X25519_KEY_LEN..2 * X25519_KEY_LEN].copy_from_slice(&inputs.dh2.0);
            km[2 * X25519_KEY_LEN..3 * X25519_KEY_LEN].copy_from_slice(&inputs.dh3.0);
            KeyMaterial::WithoutOpk(km)
        }

        Some(dh4) => {
            let mut km = [0u8; KM_LEN_WITH_OPK];

            km[0..X25519_KEY_LEN].copy_from_slice(&inputs.dh1.0);
            km[X25519_KEY_LEN..2 * X25519_KEY_LEN].copy_from_slice(&inputs.dh2.0);
            km[2 * X25519_KEY_LEN..3 * X25519_KEY_LEN].copy_from_slice(&inputs.dh3.0);
            km[3 * X25519_KEY_LEN..4 * X25519_KEY_LEN].copy_from_slice(&dh4.0);

            KeyMaterial::WithOpk(km)
        }
    }
}

/// Assemble X3DH input key material (KM) from Alice-side DH outputs.
///
/// X3DH order:
///  1. DH(IK_A, SPK_B)
///  2. DH(EK_A, IK_B)
///  3. DH(EK_A, SPK_B)
///  4. Optional DH(EK_A, OPK_B)
///
/// This order is security-critical and must match Bob's assembly logic.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    result.len() == expected_km_len(inputs.dh4.is_some())
)]
pub fn assemble_km_from_alice_inputs(inputs: &AliceDhInputs) -> KeyMaterial {
    let ordered = ordered_from_alice(inputs);
    assemble_km_from_ordered_inputs(&ordered)
}

/// Assemble X3DH input key material (KM) from Bob-side DH outputs.
///
/// X3DH order:
///  1. DH(SPK_B, IK_A)
///  2. DH(IK_B, EK_A)
///  3. DH(SPK_B, EK_A)
///  4. Optional DH(OPK_B, EK_A)
///
/// Positionally, these outputs should match Alice's transcript inputs.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    result.len() == expected_km_len(inputs.dh4.is_some())
)]
pub fn assemble_km_from_bob_inputs(inputs: &BobDhInputs) -> KeyMaterial {
    let ordered = ordered_from_bob(inputs);
    assemble_km_from_ordered_inputs(&ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::dh;
    use crate::types::{AliceDhInputs, BobDhInputs};

    #[test]
    fn alice_km_without_opk_has_expected_length() {
        let alice = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: None,
        };

        let km = assemble_km_from_alice_inputs(&alice);
        assert_eq!(km.len(), KM_LEN_WITHOUT_OPK);
        assert!(is_valid_km_len(&km.as_vec()));
    }

    #[test]
    fn alice_km_with_opk_has_expected_length() {
        let alice = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: Some(dh(0x04)),
        };

        let km = assemble_km_from_alice_inputs(&alice);
        assert_eq!(km.len(), KM_LEN_WITH_OPK);
        assert!(is_valid_km_len(&km.as_vec()));
    }

    #[test]
    fn bob_km_without_opk_has_expected_length() {
        let bob = BobDhInputs {
            dh1: dh(0x0a),
            dh2: dh(0x0b),
            dh3: dh(0x0c),
            dh4: None,
        };

        let km = assemble_km_from_bob_inputs(&bob);
        assert_eq!(km.len(), KM_LEN_WITHOUT_OPK);
        assert!(is_valid_km_len(&km.as_vec()));
    }

    #[test]
    fn alice_and_bob_matching_inputs_produce_same_km_without_opk() {
        let alice = AliceDhInputs {
            dh1: dh(0x11),
            dh2: dh(0x22),
            dh3: dh(0x33),
            dh4: None,
        };

        let bob = BobDhInputs {
            dh1: dh(0x11),
            dh2: dh(0x22),
            dh3: dh(0x33),
            dh4: None,
        };

        let km_a = assemble_km_from_alice_inputs(&alice);
        let km_b = assemble_km_from_bob_inputs(&bob);

        assert_eq!(km_a, km_b);
    }

    #[test]
    fn alice_and_bob_matching_inputs_produce_same_km_with_opk() {
        let alice = AliceDhInputs {
            dh1: dh(0xaa),
            dh2: dh(0xbb),
            dh3: dh(0xcc),
            dh4: Some(dh(0xdd)),
        };

        let bob = BobDhInputs {
            dh1: dh(0xaa),
            dh2: dh(0xbb),
            dh3: dh(0xcc),
            dh4: Some(dh(0xdd)),
        };

        let km_a = assemble_km_from_alice_inputs(&alice);
        let km_b = assemble_km_from_bob_inputs(&bob);

        assert_eq!(km_a, km_b);
    }

    #[test]
    fn mismatched_inputs_produce_different_km() {
        let alice = AliceDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x02),
            dh3: dh(0x03),
            dh4: None,
        };

        let bob = BobDhInputs {
            dh1: dh(0x01),
            dh2: dh(0x99),
            dh3: dh(0x03),
            dh4: None,
        };

        let km_a = assemble_km_from_alice_inputs(&alice);
        let km_b = assemble_km_from_bob_inputs(&bob);

        assert_ne!(km_a, km_b);
    }

    #[test]
    fn expected_km_len_matches_cases() {
        assert_eq!(expected_km_len(false), KM_LEN_WITHOUT_OPK);
        assert_eq!(expected_km_len(true), KM_LEN_WITH_OPK);
    }
}
