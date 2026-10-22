# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Reference example. Not compiled by this checkout. See README.adoc.

defmodule Verisim.Nif do
  @moduledoc """
  The only native entry point for the entity.

  `use Quintessence.Nif` generates `@on_load`, which checks the receipt's
  binary hash, target, obligations, and schedule before calling
  `:erlang.load_nif/2`. A failure prevents this module from loading.
  """

  use Quintessence.Nif,
    otp_app: :verisim,
    library: "verisim_nif",
    abi: Verisim.Abi,
    receipt: "priv/receipts/verisim_nif.receipt.json"

  @doc "SHA-256 (production: BLAKE3) of the payload, seeded by the entity version."
  @nif :hash, schedule: :auto, budget_us: 180
  def hash(payload, seed), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Basis-point drift between two 32-byte digests."
  @nif :drift, schedule: :auto, budget_us: 240
  def drift(a, b), do: :erlang.nif_error(:nif_not_loaded)
end
