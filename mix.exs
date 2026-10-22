# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

defmodule Quintessence.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/hyperpolymath/quintessence"

  def project do
    [
      app: :quintessence,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      description:
        "Three-layer formal verification suite for Elixir/OTP/BEAM: sequential pure subsets with TINI + MPR R5 non-interference, choreographic K-CUT GenServer protocols, and Idris2 QTT ABI + verified Zig NIFs under MaxPlus 1 ms scheduler bounds, backed by Z3, CVC5, Alethe proof checking, and ECHIDNA mutation gates.",
      package: package(),
      deps: deps(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "examples/quintessence/lib"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    []
  end

  defp package do
    [
      licenses: ["MPL-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.adoc LICENSE src/core src/interface/ffi)
    ]
  end

  defp aliases do
    [
      "verify.all": ["verify --strict"]
    ]
  end
end
