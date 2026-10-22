# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

defmodule Mix.Tasks.Verify do
  @shortdoc "Run Quintessence formal verification across Layers A, B, and C"
  @moduledoc """
  Runs the native `quintessence` verification pipeline and halts the BEAM VM
  with documented exit status `1..5` on failure (since Mix ignores `run/1`'s
  return value).
  """

  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    case Quintessence.CLI.run(["verify" | argv]) do
      {:ok, out} ->
        Mix.shell().info(out)
        :ok

      {:error, status, out} ->
        Mix.shell().error(out)
        System.halt(Quintessence.Error.exit_code(status))
    end
  end
end

defmodule Mix.Tasks.Quintessence.Doctor do
  @shortdoc "Probe required and optional Quintessence verification binaries"
  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    case Quintessence.CLI.run(["doctor" | argv]) do
      {:ok, out} ->
        Mix.shell().info(out)
        :ok

      {:error, status, out} ->
        Mix.shell().error(out)
        System.halt(Quintessence.Error.exit_code(status))
    end
  end
end

defmodule Mix.Tasks.Quintessence.Explain do
  @shortdoc "Explain a Quintessence error code, formal rule, falsifier, and remedy"
  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    case Quintessence.CLI.run(["explain" | argv]) do
      {:ok, out} ->
        Mix.shell().info(out)
        :ok

      {:error, status, out} ->
        Mix.shell().error(out)
        System.halt(Quintessence.Error.exit_code(status))
    end
  end
end

defmodule Mix.Tasks.Quintessence.Receipt do
  @shortdoc "Inspect or cryptographically verify a Quintessence JCS receipt"
  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    case Quintessence.CLI.run(["receipt" | argv]) do
      {:ok, out} ->
        Mix.shell().info(out)
        :ok

      {:error, status, out} ->
        Mix.shell().error(out)
        System.halt(Quintessence.Error.exit_code(status))
    end
  end
end
