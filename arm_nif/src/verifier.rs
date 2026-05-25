use crate::error::ArmNifError;
use arm_core::instance::{AppData, Payload, Transaction};
use rustler::NifResult;

fn decode_tx(tx_bytes: &[u8]) -> Result<Transaction, ArmNifError> {
    Ok(bincode::serde::decode_from_slice(tx_bytes, bincode::config::standard())?.0)
}

/// The four payload categories (resource, encryption, external, discovery) as
/// `(blob, deletion_criterion)` lists — the boundary form crossing to Elixir as
/// `{binary, boolean}` tuples.
type AppDataBlobs = (
    Vec<(Vec<u8>, bool)>,
    Vec<(Vec<u8>, bool)>,
    Vec<(Vec<u8>, bool)>,
    Vec<(Vec<u8>, bool)>,
);

fn app_data_blobs(ad: &AppData) -> AppDataBlobs {
    let conv = |ps: &[Payload]| -> Vec<(Vec<u8>, bool)> {
        ps.iter()
            .map(|p| (p.data.clone(), p.deletion_criterion))
            .collect()
    };
    (
        conv(&ad.resource_payload),
        conv(&ad.encryption_payload),
        conv(&ad.external_payload),
        conv(&ad.discovery_payload),
    )
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_transaction(tx_bytes: Vec<u8>) -> NifResult<bool> {
    Ok(decode_tx(&tx_bytes)?.verify().is_ok())
}

/// Decode + verify once, returning the consumed/created resources (each as
/// `(tag, app_data_blobs)`) and the consumed roots. Errors on decode failure or
/// any verification failure (carrying the specific `ArmError`).
#[rustler::nif(schedule = "DirtyCpu")]
fn verify_and_extract(
    tx_bytes: Vec<u8>,
) -> NifResult<(
    Vec<(Vec<u8>, AppDataBlobs)>,
    Vec<(Vec<u8>, AppDataBlobs)>,
    Vec<Vec<u8>>,
)> {
    let tx = decode_tx(&tx_bytes)?;
    tx.verify().map_err(ArmNifError::from)?;
    let consumed_with_appdata = tx
        .units
        .iter()
        .flat_map(|u| u.action_instance.consumed.iter())
        .map(|c| (c.nullifier.to_vec(), app_data_blobs(&c.app_data)))
        .collect();
    let created_with_appdata = tx
        .units
        .iter()
        .flat_map(|u| u.action_instance.created.iter())
        .map(|c| (c.commitment.to_vec(), app_data_blobs(&c.app_data)))
        .collect();
    let roots = tx.roots().into_iter().map(|r| r.to_vec()).collect();
    Ok((consumed_with_appdata, created_with_appdata, roots))
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
