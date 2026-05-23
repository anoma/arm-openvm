use crate::error::ArmNifError;
use arm_core::instance::Transaction;
use rustler::NifResult;

fn decode_tx(tx_bytes: &[u8]) -> Result<Transaction, ArmNifError> {
    Ok(bincode::serde::decode_from_slice(tx_bytes, bincode::config::standard())?.0)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_transaction(tx_bytes: Vec<u8>) -> NifResult<bool> {
    Ok(decode_tx(&tx_bytes)?.verify().is_ok())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_nullifiers(tx_bytes: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    Ok(decode_tx(&tx_bytes)?
        .nullifiers()
        .into_iter()
        .map(|n| n.to_vec())
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_commitments(tx_bytes: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    Ok(decode_tx(&tx_bytes)?
        .commitments()
        .into_iter()
        .map(|c| c.to_vec())
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_roots(tx_bytes: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    Ok(decode_tx(&tx_bytes)?
        .roots()
        .into_iter()
        .map(|r| r.to_vec())
        .collect())
}
