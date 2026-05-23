mod error;
mod verifier;

rustler::init!(
    "Elixir.ArmOpenvm.Verifier",
    [
        verifier::verify_transaction,
        verifier::transaction_nullifiers,
        verifier::transaction_commitments,
        verifier::transaction_roots,
    ]
);
