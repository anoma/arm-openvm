use crate::error::ArmNifError;
use arm_core::instance::{AppData, Payload, Transaction};
use rustler::{Binary, Env, NifResult, OwnedBinary};

fn decode_tx(tx_bytes: &[u8]) -> Result<Transaction, ArmNifError> {
    Ok(bincode::serde::decode_from_slice(tx_bytes, bincode::config::standard())?.0)
}

/// Copy bytes into a freshly-allocated Erlang binary.
fn to_bin<'a>(env: Env<'a>, bytes: &[u8]) -> Binary<'a> {
    let mut bin = OwnedBinary::new(bytes.len()).expect("OwnedBinary allocation failed");
    bin.as_mut_slice().copy_from_slice(bytes);
    bin.release(env)
}

/// The four payload categories (resource, encryption, external, discovery) as
/// `(blob, deletion_criterion)` lists — each blob an Erlang binary, so the pair
/// crosses to Elixir as `{binary, boolean}`.
type AppDataBlobs<'a> = (
    Vec<(Binary<'a>, bool)>,
    Vec<(Binary<'a>, bool)>,
    Vec<(Binary<'a>, bool)>,
    Vec<(Binary<'a>, bool)>,
);

fn app_data_blobs<'a>(env: Env<'a>, ad: &AppData) -> AppDataBlobs<'a> {
    let conv = |ps: &[Payload]| -> Vec<(Binary<'a>, bool)> {
        ps.iter()
            .map(|p| (to_bin(env, &p.data), p.deletion_criterion))
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
fn verify_transaction(tx_bytes: Binary) -> NifResult<bool> {
    Ok(decode_tx(tx_bytes.as_slice())?.verify().is_ok())
}

/// Decode + verify once, returning the consumed/created resources (each as
/// `(tag, app_data_blobs)`) and the consumed roots. Errors on decode failure or
/// any verification failure (carrying the specific `ArmError`).
#[rustler::nif(schedule = "DirtyCpu")]
fn verify_and_extract<'a>(
    env: Env<'a>,
    tx_bytes: Binary<'a>,
) -> NifResult<(
    Vec<(Binary<'a>, AppDataBlobs<'a>)>,
    Vec<(Binary<'a>, AppDataBlobs<'a>)>,
    Vec<Binary<'a>>,
)> {
    let tx = decode_tx(tx_bytes.as_slice())?;
    tx.verify().map_err(ArmNifError::from)?;
    let consumed_with_appdata = tx
        .units
        .iter()
        .flat_map(|u| u.action_instance.consumed.iter())
        .map(|c| (to_bin(env, &c.nullifier), app_data_blobs(env, &c.app_data)))
        .collect();
    let created_with_appdata = tx
        .units
        .iter()
        .flat_map(|u| u.action_instance.created.iter())
        .map(|c| (to_bin(env, &c.commitment), app_data_blobs(env, &c.app_data)))
        .collect();
    let roots = tx.roots().iter().map(|r| to_bin(env, r)).collect();
    Ok((consumed_with_appdata, created_with_appdata, roots))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_nullifiers<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    Ok(decode_tx(tx_bytes.as_slice())?
        .nullifiers()
        .iter()
        .map(|n| to_bin(env, n))
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_commitments<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    Ok(decode_tx(tx_bytes.as_slice())?
        .commitments()
        .iter()
        .map(|c| to_bin(env, c))
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_roots<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    Ok(decode_tx(tx_bytes.as_slice())?
        .roots()
        .iter()
        .map(|r| to_bin(env, r))
        .collect())
}
