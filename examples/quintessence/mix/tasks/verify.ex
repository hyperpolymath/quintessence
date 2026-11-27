# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# DESIGN SKETCH. THIS FILE DOES NOT RUN.
# It calls Quintessence.Project, .Frontend, .Echidna, .Batch, .Mutation, .Gate
# and .Report, and none of them exists in this repository (nor does
# Quintessence.Doctor; only Quintessence.Error is defined, in lib/). It is not
# compiled by this checkout. Plan stage Q2 (docs/plan/ULTRAPLAN.adoc) is the
# stage that would make it real. Today the working entry point is the
# `quintessence` CLI (src/interface/ffi). See README.adoc.

defmodule Mix.Tasks.Verify do
  @moduledoc """
  Verify the quintessence subset end to end.

      mix verify [--module MODULE] [--layer a|b|c] [--strict] [--receipt]
                 [--replay] [--format human|json|sarif]
  """

  use Mix.Task

  @shortdoc "Verify the quintessence subset end to end"
  @requirements ["compile"]

  @impl Mix.Task
  def run(argv) do
    {opts, _args, invalid} =
      OptionParser.parse(argv,
        strict: [
          module: :string,
          layer: :string,
          strict: :boolean,
          receipt: :boolean,
          replay: :boolean,
          allow_oracle: :boolean,
          format: :string
        ]
      )

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    # Mix ignores the return value of run/1. The stable exit codes are the
    # contract, so the task halts explicitly.
    with {:ok, project} <- Quintessence.Project.load(),
         :ok <- Quintessence.Doctor.check!(project),
         {:ok, qir} <- Quintessence.Frontend.elaborate(project, opts),
         {:ok, obligations} <- Quintessence.Project.obligations(qir, opts),
         {:ok, warrants} <- Quintessence.Echidna.dispatch(obligations, project),
         {:ok, receipts} <- Quintessence.Batch.check(warrants, project),
         :ok <- Quintessence.Mutation.check(qir, project),
         :ok <- Quintessence.Gate.check(receipts, project, opts) do
      Quintessence.Report.print(receipts, opts)
      :ok
    else
      {:error, %Quintessence.Error{code: code} = err} ->
        Quintessence.Report.error(err)
        System.halt(Quintessence.Error.exit_code(code))
    end
  end
end
