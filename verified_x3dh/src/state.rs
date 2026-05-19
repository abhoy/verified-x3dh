//! state.rs
//!
//! explicit protocol phases:
//! AliceStart -> AliceSentInitial -> AliceEstablished
//! BobReady -> BobReceivedInitial -> BobEstablished
//! 
//! verification goal includes:
//! 
//! invalid transition rejection
//! no "key-before-message" behavior
//! protocol phase invariants
//!
//! Minimal state layer for the verification-friendly X3DH core.
//!
//! This module models only protocol progression and Bob OPK consumption.
//! It does not perform crypto, networking, storage, or adversarial reasoning.

use crate::handshake_core::{
    alice_initiate_core, bob_receive_core, AliceInitiateCoreInputs, BobReceiveCoreInputs,
};
use crate::types::{
    AliceHandshakeResult, AliceInitialMessage, BobHandshakeResult, BobLocalState,
    HandshakeError,
};

/// Alice protocol state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliceProtocolState {
    /// Alice has not sent an initial message.
    Start,

    /// Alice sent the initial message and locally derived the shared secret.
    SentInitial {
        result: AliceHandshakeResult,
    },

    /// Alice considers the session established.
    Established {
        result: AliceHandshakeResult,
    },
}

/// Bob protocol state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BobProtocolState {
    /// Bob is ready to receive Alice's initial message.
    Ready {
        local_state: BobLocalState,
    },

    /// Bob processed Alice's initial message and derived the shared secret.
    ReceivedInitial {
        local_state: BobLocalState,
        message: AliceInitialMessage,
        result: BobHandshakeResult,
    },

    /// Bob considers the session established.
    Established {
        local_state: BobLocalState,
        result: BobHandshakeResult,
    },
}

/// Return true if Bob currently has an unused one-time prekey.
#[hax_lib::ensures(|result|
    result == matches!(state, BobProtocolState::Ready { local_state }
        if local_state.one_time_prekey.is_some())
)]
pub fn bob_ready_has_opk(state: &BobProtocolState) -> bool {
    match state {
        BobProtocolState::Ready { local_state } => local_state.one_time_prekey.is_some(),
        _ => false,
    }
}

/// Alice transition:
/// Start -> SentInitial.
///
/// The pure handshake core does the actual deterministic computation.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(AliceProtocolState::SentInitial { .. }) => true,
        Ok(_) => false,
        Err(_) => true,
    }
)]
pub fn alice_start(
    state: AliceProtocolState,
    inputs: &AliceInitiateCoreInputs,
) -> Result<AliceProtocolState, HandshakeError> {
    match state {
        AliceProtocolState::Start => {
            let result = alice_initiate_core(inputs)?;
            Ok(AliceProtocolState::SentInitial { result })
        }
        _ => Err(HandshakeError::MalformedMessage),
    }
}

/// Property:
/// `alice_start` rejects non-start Alice states.
///
/// This captures invalid transition rejection:
/// Alice may only run the start transition from `Start`.
#[hax_lib::include]
#[hax_lib::ensures(|result|
///    matches!(result, Err(HandshakeError::MalformedMessage))
    match state {
        AliceProtocolState::Start => true,
        _ => matches!(result, Err(HandshakeError::MalformedMessage)),
    }
)]
pub fn prop_alice_start_rejects_non_start(
    state: AliceProtocolState,
    inputs: &AliceInitiateCoreInputs,
) -> Result<AliceProtocolState, HandshakeError> {
    alice_start(state, inputs)
}

/// Property:
/// `alice_establish` rejects states other than `SentInitial`.
///
/// This rules out “established-before-message” behavior on Alice's side.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match state {
        AliceProtocolState::SentInitial { .. } => true,
        _ => matches!(result, Err(HandshakeError::MalformedMessage)),
    }
)]
///    matches!(result, Err(HandshakeError::MalformedMessage))
pub fn prop_alice_establish_rejects_without_sent_initial(
    state: AliceProtocolState,
) -> Result<AliceProtocolState, HandshakeError> {
    alice_establish(state)
}

/// Alice transition:
/// SentInitial -> Established.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(AliceProtocolState::Established { .. }) => true,
        Ok(_) => false,
        Err(_) => true,
    }
)]
pub fn alice_establish(
    state: AliceProtocolState,
) -> Result<AliceProtocolState, HandshakeError> {
    match state {
        AliceProtocolState::SentInitial { result } => {
            Ok(AliceProtocolState::Established { result })
        }
        _ => Err(HandshakeError::MalformedMessage),
    }
}

/// Consume Bob's one-time prekey after a successful receive.
///
/// In this first model, successful OPK use removes the local OPK.
/// If no OPK was referenced, Bob's local OPK state is left unchanged.
#[hax_lib::ensures(|result|
    if message.one_time_prekey_id.is_some() {
        result.one_time_prekey.is_none()
    } else {
        true
    }
)]
fn consume_bob_opk_after_receive(
    mut local_state: BobLocalState,
    message: &AliceInitialMessage,
) -> BobLocalState {
    if message.one_time_prekey_id.is_some() {
        local_state.one_time_prekey = None;
    }

    local_state
}

/// Bob transition:
/// Ready -> ReceivedInitial.
///
/// The pure handshake core validates the message and derives the shared secret.
/// If Alice referenced a one-time prekey and Bob accepts, that OPK is consumed.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(BobProtocolState::ReceivedInitial { local_state, message, .. }) =>
            if message.one_time_prekey_id.is_some() {
                local_state.one_time_prekey.is_none()
            } else {
                true
            },
        Ok(_) => false,
        Err(_) => true,
    }
)]
pub fn bob_receive(
    state: BobProtocolState,
    inputs: &BobReceiveCoreInputs,
) -> Result<BobProtocolState, HandshakeError> {
    match state {
        BobProtocolState::Ready { local_state } => {
            let result = bob_receive_core(inputs)?;
            let next_local_state =
                consume_bob_opk_after_receive(local_state, &inputs.alice_message);

            Ok(BobProtocolState::ReceivedInitial {
                local_state: next_local_state,
                message: inputs.alice_message.clone(),
                result,
            })
        }
        _ => Err(HandshakeError::MalformedMessage),
    }
}

/// Property:
/// If Bob successfully processes a message that references an OPK,
/// the resulting Bob state no longer contains that OPK.
///
/// This models one-time prekey consumption.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(BobProtocolState::ReceivedInitial { local_state, message, .. }) =>
            if message.one_time_prekey_id.is_some() {
                local_state.one_time_prekey.is_none()
            } else {
                true
            },
        Ok(_) => false,
        Err(_) => true,
    }
)]
pub fn prop_bob_receive_consumes_opk_when_referenced(
    state: BobProtocolState,
    inputs: &BobReceiveCoreInputs,
) -> Result<BobProtocolState, HandshakeError> {
    bob_receive(state, inputs)
}

/// Property:
/// `bob_receive` rejects non-ready Bob states.
///
/// Bob may only process Alice's initial message from `Ready`.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match state {
        BobProtocolState::Ready { .. } => true,
        _ => matches!(result, Err(HandshakeError::MalformedMessage)),
    }
)]
///    matches!(result, Err(HandshakeError::MalformedMessage))
pub fn prop_bob_receive_rejects_non_ready(
    state: BobProtocolState,
    inputs: &BobReceiveCoreInputs,
) -> Result<BobProtocolState, HandshakeError> {
    bob_receive(state, inputs)
}

/// Property:
/// `bob_establish` rejects states other than `ReceivedInitial`.
///
/// This rules out “established-before-message” behavior on Bob's side.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match state {
        BobProtocolState::ReceivedInitial { .. } => true,
        _ => matches!(result, Err(HandshakeError::MalformedMessage)),
    }
)]
///    matches!(result, Err(HandshakeError::MalformedMessage))
pub fn prop_bob_establish_rejects_without_received_initial(
    state: BobProtocolState,
) -> Result<BobProtocolState, HandshakeError> {
    bob_establish(state)
}

/// Bob transition:
/// ReceivedInitial -> Established.
#[hax_lib::include]
#[hax_lib::ensures(|result|
    match result {
        Ok(BobProtocolState::Established { .. }) => true,
        Ok(_) => false,
        Err(_) => true,
    }
)]
pub fn bob_establish(
    state: BobProtocolState,
) -> Result<BobProtocolState, HandshakeError> {
    match state {
        BobProtocolState::ReceivedInitial {
            local_state,
            result,
            ..
        } => Ok(BobProtocolState::Established {
            local_state,
            result,
        }),
        _ => Err(HandshakeError::MalformedMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        dh, sample_alice_public, sample_bob_public_with_opk,
        sample_bob_public_without_opk, sample_bob_state_with_opk,
        sample_bob_state_without_opk,
    };
    use crate::types::{
        AliceDhInputs, BobDhInputs, Ciphertext, Nonce, Plaintext,
    };

    #[test]
    fn alice_start_moves_to_sent_initial() {
        let inputs = AliceInitiateCoreInputs {
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
            ciphertext: Ciphertext(vec![1, 2, 3]),
            info: None,
        };

        let next = alice_start(AliceProtocolState::Start, &inputs).unwrap();

        assert!(matches!(next, AliceProtocolState::SentInitial { .. }));
    }

    #[test]
    fn alice_establish_moves_to_established() {
        let inputs = AliceInitiateCoreInputs {
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
            ciphertext: Ciphertext(vec![1, 2, 3]),
            info: None,
        };

        let sent = alice_start(AliceProtocolState::Start, &inputs).unwrap();
        let established = alice_establish(sent).unwrap();

        assert!(matches!(established, AliceProtocolState::Established { .. }));
    }

    #[test]
    fn bob_receive_without_opk_keeps_state_shape() {
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
            ciphertext: Ciphertext(vec![9]),
            info: None,
        };

        let alice_result = alice_initiate_core(&alice_inputs).unwrap();

        let bob_inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: alice_result.initial_message,
            dh_inputs: BobDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: None,
            },
            plaintext: Plaintext(b"ok".to_vec()),
            info: None,
        };

        let next = bob_receive(
            BobProtocolState::Ready {
                local_state: sample_bob_state_without_opk(),
            },
            &bob_inputs,
        )
        .unwrap();

        assert!(matches!(next, BobProtocolState::ReceivedInitial { .. }));
    }

    #[test]
    fn bob_receive_with_opk_consumes_opk() {
        let alice_inputs = AliceInitiateCoreInputs {
            alice_public: sample_alice_public(),
            bob_public: sample_bob_public_with_opk(),
            dh_inputs: AliceDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: Some(dh(0x40)),
            },
            signed_prekey_is_valid: true,
            nonce: Nonce([2u8; 12]),
            ciphertext: Ciphertext(vec![9]),
            info: None,
        };

        let alice_result = alice_initiate_core(&alice_inputs).unwrap();

        let bob_inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_with_opk(),
            alice_message: alice_result.initial_message,
            dh_inputs: BobDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: Some(dh(0x40)),
            },
            plaintext: Plaintext(b"ok".to_vec()),
            info: None,
        };

        let next = bob_receive(
            BobProtocolState::Ready {
                local_state: sample_bob_state_with_opk(),
            },
            &bob_inputs,
        )
        .unwrap();

        match next {
            BobProtocolState::ReceivedInitial { local_state, .. } => {
                assert!(local_state.one_time_prekey.is_none());
            }
            _ => panic!("expected ReceivedInitial"),
        }
    }

    #[test]
    fn bob_establish_moves_to_established() {
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
            ciphertext: Ciphertext(vec![9]),
            info: None,
        };

        let alice_result = alice_initiate_core(&alice_inputs).unwrap();

        let bob_inputs = BobReceiveCoreInputs {
            bob_state: sample_bob_state_without_opk(),
            alice_message: alice_result.initial_message,
            dh_inputs: BobDhInputs {
                dh1: dh(0x10),
                dh2: dh(0x20),
                dh3: dh(0x30),
                dh4: None,
            },
            plaintext: Plaintext(b"ok".to_vec()),
            info: None,
        };

        let received = bob_receive(
            BobProtocolState::Ready {
                local_state: sample_bob_state_without_opk(),
            },
            &bob_inputs,
        )
        .unwrap();

        let established = bob_establish(received).unwrap();

        assert!(matches!(established, BobProtocolState::Established { .. }));
    }
}