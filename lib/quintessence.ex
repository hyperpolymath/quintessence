# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

defmodule Quintessence do
  @moduledoc """
  Elixir interface to the Quintessence three-layer formal verification suite.

  Delegates parsing, G0a-G0c firewall checks, `qir/v1` elaboration, Layer A
  SMT/BitVec/TINI verification, Layer B `K-CUT` typing & `k = 12` symbolic
  bounded model checking, Layer C `MaxPlus` WCET & `dlopen` ABI checks, Alethe
  proof-DAG kernel checking, and 6-kind ECHIDNA mutation analysis to the native
  `quintessence` binary built from `src/interface/ffi`.
  """

  alias Quintessence.CLI

  @spec verify([String.t()], keyword()) :: {:ok, String.t()} | {:error, non_neg_integer(), String.t()}
  def verify(paths \\ ["lib"], opts \\ []) do
    CLI.run(["verify" | paths] ++ build_flags(opts))
  end

  @spec explain(String.t()) :: {:ok, String.t()} | {:error, non_neg_integer(), String.t()}
  def explain(code), do: CLI.run(["explain", code])

  @spec doctor(keyword()) :: {:ok, String.t()} | {:error, non_neg_integer(), String.t()}
  def doctor(opts \\ []) do
    flags = if opts[:format] == :json, do: ["--format", "json"], else: []
    CLI.run(["doctor" | flags])
  end

  defp build_flags(opts) do
    Enum.flat_map(opts, fn
      {:module, m} when is_binary(m) -> ["--module", m]
      {:module, m} when is_atom(m) -> ["--module", inspect(m)]
      {:layer, l} -> ["--layer", to_string(l)]
      {:strict, true} -> ["--strict"]
      {:require_level_5, true} -> ["--require-level-5"]
      {:out_dir, d} -> ["--out-dir", d]
      {:format, f} -> ["--format", to_string(f)]
      {:no_mutation, true} -> ["--no-mutation"]
      {:mutation_threshold, t} -> ["--mutation-threshold", to_string(t)]
      _ -> []
    end)
  end
end
