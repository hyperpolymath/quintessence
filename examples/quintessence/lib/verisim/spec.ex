# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Reference example. Not compiled by this checkout. See README.adoc.

defmodule Verisim.Spec do
  @moduledoc """
  Pure logical model for the VeriSimDB entity.

  This module is Layer A: no processes, no ports, no files, no clocks. The
  functions here are the model that the NIF receipt and the GenServer contracts
  refer to. The hash is SHA-256 so the example is executable with OTP's crypto
  application; a production build swaps in BLAKE3 and a corresponding receipt.
  """

  use Quintessence.Face, layer: :a

  import Bitwise

  @max_payload 1_048_576
  @max_drift_bp 2_500

  @doc """
  Logical digest model. `:crypto.hash/2` is an OTP primitive; the firewall
  treats it as a trusted primitive with a pinned OTP receipt.
  """
  @pre spec(byte_size(payload) <= @max_payload)
  @post spec(byte_size(result) == 32)
  def digest_of(payload), do: :crypto.hash(:sha256, payload)

  @doc """
  Drift in basis points: the popcount of the XOR of two 32-byte digests,
  scaled to 0..10000. The bound is proved, not measured.
  """
  @pre spec(byte_size(a) == 32 and byte_size(b) == 32)
  @post spec(result >= 0 and result <= 10_000)
  def drift_of(a, b) do
    bits =
      a
      |> :binary.bin_to_list()
      |> Enum.zip(:binary.bin_to_list(b))
      |> Enum.reduce(0, fn {x, y}, acc -> acc + popcount(bxor(x, y)) end)

    div(bits * 10_000, 256)
  end

  @doc "The drift guard used by the entity handler."
  @pre spec(drift <= 10_000)
  @post spec(result == (drift <= @max_drift_bp))
  def acceptable_drift?(drift), do: drift <= @max_drift_bp

  @doc """
  A total recursive function, used to exercise `@measure`. The measure is the
  length of the history; the recursive call is on the tail.
  """
  @measure spec(length(history))
  @post spec(result >= 0)
  def depth(history) do
    case history do
      [] -> 0
      [_ | rest] -> 1 + depth(rest)
    end
  end

  # Private, but still total: the measure is the integer itself.
  @measure spec(n)
  defp popcount(0), do: 0
  defp popcount(n), do: 1 + popcount(band(n, n - 1))
end
