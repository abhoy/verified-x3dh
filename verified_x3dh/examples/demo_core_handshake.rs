use verified_x3dh::demo_inputs::{
    sample_alice_core_inputs_with_opk, sample_alice_core_inputs_without_opk,
    sample_bob_core_inputs_with_opk, sample_bob_core_inputs_without_opk,
    sample_bob_state_with_opk, sample_bob_state_without_opk,
};
use verified_x3dh::handshake_core::{alice_initiate_core, bob_receive_core};
use verified_x3dh::state::{
    alice_establish, alice_start, bob_establish, bob_receive, AliceProtocolState,
    BobProtocolState,
};

fn run_pure_core_without_opk() {
    let alice_inputs = sample_alice_core_inputs_without_opk();
    let bob_inputs = sample_bob_core_inputs_without_opk();

    let alice_result = alice_initiate_core(&alice_inputs).expect("Alice core should succeed");
    let bob_result = bob_receive_core(&bob_inputs).expect("Bob core should succeed");

    println!("== Pure Core Without OPK ==");
    println!("alice shared secret: {:02x?}", alice_result.shared_secret.0);
    println!("bob   shared secret: {:02x?}", bob_result.shared_secret.0);
    println!(
        "shared secrets equal: {}",
        alice_result.shared_secret == bob_result.shared_secret
    );
    println!(
        "associated data equal: {}",
        alice_result.associated_data == bob_result.associated_data
    );
    println!();
}

fn run_pure_core_with_opk() {
    let alice_inputs = sample_alice_core_inputs_with_opk();
    let bob_inputs = sample_bob_core_inputs_with_opk();

    let alice_result = alice_initiate_core(&alice_inputs).expect("Alice core should succeed");
    let bob_result = bob_receive_core(&bob_inputs).expect("Bob core should succeed");

    println!("== Pure Core With OPK ==");
    println!("alice shared secret: {:02x?}", alice_result.shared_secret.0);
    println!("bob   shared secret: {:02x?}", bob_result.shared_secret.0);
    println!(
        "shared secrets equal: {}",
        alice_result.shared_secret == bob_result.shared_secret
    );
    println!(
        "associated data equal: {}",
        alice_result.associated_data == bob_result.associated_data
    );
    println!();
}

fn run_state_machine_without_opk() {
    let alice_inputs = sample_alice_core_inputs_without_opk();
    let bob_inputs = sample_bob_core_inputs_without_opk();

    let alice_sent =
        alice_start(AliceProtocolState::Start, &alice_inputs).expect("Alice start should succeed");
    let alice_established =
        alice_establish(alice_sent).expect("Alice establish should succeed");

    let bob_received = bob_receive(
        BobProtocolState::Ready {
            local_state: sample_bob_state_without_opk(),
        },
        &bob_inputs,
    )
    .expect("Bob receive should succeed");
    let bob_established = bob_establish(bob_received).expect("Bob establish should succeed");

    println!("== State Machine Without OPK ==");
    println!("alice final state: {:?}", alice_established);
    println!("bob   final state: {:?}", bob_established);
    println!();
}

fn run_state_machine_with_opk() {
    let alice_inputs = sample_alice_core_inputs_with_opk();
    let bob_inputs = sample_bob_core_inputs_with_opk();

    let bob_has_opk_before = sample_bob_state_with_opk().one_time_prekey.is_some();

    let alice_sent =
        alice_start(AliceProtocolState::Start, &alice_inputs).expect("Alice start should succeed");
    let alice_established =
        alice_establish(alice_sent).expect("Alice establish should succeed");

    let bob_received = bob_receive(
        BobProtocolState::Ready {
            local_state: sample_bob_state_with_opk(),
        },
        &bob_inputs,
    )
    .expect("Bob receive should succeed");
    let bob_established = bob_establish(bob_received.clone()).expect("Bob establish should succeed");

    let bob_has_opk_after = match bob_received {
        BobProtocolState::ReceivedInitial { local_state, .. } => local_state.one_time_prekey.is_some(),
        _ => false,
    };

    println!("== State Machine With OPK ==");
    println!("alice final state: {:?}", alice_established);
    println!("bob   final state: {:?}", bob_established);
    println!("Bob had OPK before receive: {}", bob_has_opk_before);
    println!("Bob has OPK after receive:  {}", bob_has_opk_after);
    println!();
}

fn main() {
    println!("verification-friendly X3DH core demo");
    println!("This example exercises the abstract Rust model, not real crypto.\n");

    run_pure_core_without_opk();
    run_pure_core_with_opk();
    run_state_machine_without_opk();
    run_state_machine_with_opk();
}
