defmodule ArmOpenvm.Verifier do
  # NOTE: rustler resolves `crate: :arm_nif` to `native/arm_nif/` relative to the
  # mix project root by default. In this workspace `arm_nif` lives at the repo root,
  # so set `path:` to wherever the consuming mix project can reach it, e.g.
  #   use Rustler, otp_app: :arm_openvm, crate: :arm_nif, path: "arm_nif"
  use Rustler,
    otp_app: :arm_openvm,
    crate: :arm_nif

  @moduledoc """
  NIF bindings for verifying arm-openvm resource machine transactions.

  All functions take a bincode-encoded `arm_core::instance::Transaction` as a binary.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @typedoc "A payload blob with its deletion criterion."
  @type blob :: {binary(), boolean()}

  @typedoc "The four payload categories: {resource, encryption, external, discovery}."
  @type app_data_blobs :: {[blob()], [blob()], [blob()], [blob()]}

  @doc """
  Verify a bincode-encoded Transaction.

  Returns `true` if every action's compliance proof verifies, the revealed
  instances match, nullifiers/commitments are disjoint, and the delta proof checks;
  `false` if any of those soundness checks fail; `{:error, reason}` if the bytes
  fail to decode.
  """
  @spec verify_transaction(binary()) :: nif_result(boolean())
  def verify_transaction(_tx_bytes), do: error()

  @doc """
  Decode + verify a transaction in one pass and return its effects
  needed for global checks and storage.
  """
  @spec verify_and_extract(binary()) ::
          {[{binary(), app_data_blobs()}], [{binary(), app_data_blobs()}], [binary()]}
          | {:error, term()}
  def verify_and_extract(_tx_bytes), do: error()

  @doc "All nullifiers (32-byte binaries) in the transaction, in transaction order."
  @spec transaction_nullifiers(binary()) :: nif_result(list(binary()))
  def transaction_nullifiers(_tx_bytes), do: error()

  @doc "All commitments (32-byte binaries) in the transaction, in transaction order."
  @spec transaction_commitments(binary()) :: nif_result(list(binary()))
  def transaction_commitments(_tx_bytes), do: error()

  @doc """
  The set of consumed-resource roots in the transaction, as a deduplicated,
  sorted list of 32-byte binaries. Build a `MapSet` from it to check containment
  against the historical roots set.
  """
  @spec transaction_roots(binary()) :: nif_result(list(binary()))
  def transaction_roots(_tx_bytes), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end
