# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

defmodule Quintessence.CLI do
  @moduledoc """
  Locates and executes the compiled native `quintessence` verifier binary.
  """

  @candidate_rel_paths [
    "src/interface/ffi/zig-out/bin/quintessence",
    "priv/native/quintessence"
  ]

  @spec executable!() :: String.t()
  def executable! do
    cond do
      env_bin = System.get_env("QUINTESSENCE_BIN") ->
        env_bin

      local = Enum.find(@candidate_rel_paths, &File.regular?/1) ->
        Path.expand(local)

      path_bin = System.find_executable("quintessence") ->
        path_bin

      true ->
        raise "quintessence native binary not built; run `just build` first (error Q-901)"
    end
  end

  @spec run([String.t()]) :: {:ok, String.t()} | {:error, non_neg_integer(), String.t()}
  def run(args) when is_list(args) do
    bin = executable!()

    case System.cmd(bin, args, stderr_to_stdout: true) do
      {out, 0} -> {:ok, out}
      {out, exit_status} -> {:error, exit_status, out}
    end
  end
end

defmodule Quintessence.Error do
  @moduledoc """
  Deterministic process exit-code contract (`0..5`) matching `src/core/errors.zig`.
  """

  @spec exit_code(String.t() | non_neg_integer()) :: non_neg_integer()
  def exit_code(status) when is_integer(status) and status in 0..5, do: status
  def exit_code("Q-901"), do: 3
  def exit_code("Q-201"), do: 2
  def exit_code("Q-902"), do: 2
  def exit_code(code) when code in ["Q-301", "Q-303", "Q-502", "Q-503", "Q-504", "Q-905"], do: 4
  def exit_code(code) when code in ["Q-601", "Q-602", "Q-603", "Q-604"], do: 5
  def exit_code(_), do: 1
end

defmodule Quintessence.Tracer do
  @moduledoc """
  Compile-time Elixir `Code.Tracer` enforcing Stage 1 G0a-G0c firewall bans
  during `mix compile`.
  """

  @behaviour Code.Tracer

  @impl true
  def trace({:remote_function, meta, Code, fun, _arity}, env)
      when fun in [:eval_string, :eval_quoted, :eval_file] do
    raise CompileError,
      file: env.file,
      line: Keyword.get(meta, :line, 1),
      description: "[Q-101] Dynamic evaluation Code.#{fun} is forbidden by Quintessence G0a firewall"
  end

  def trace({:remote_function, meta, Kernel, :apply, 3}, env) do
    raise CompileError,
      file: env.file,
      line: Keyword.get(meta, :line, 1),
      description: "[Q-102] Dynamic Kernel.apply/3 violates Quintessence G0c closed call-graph rule"
  end

  def trace({:remote_function, meta, :erlang, :load_nif, 2}, env) do
    unless Module.defines_type?(env.module, {:__quintessence_nif__, 0}) do
      raise CompileError,
        file: env.file,
        line: Keyword.get(meta, :line, 1),
        description: "[Q-105] Raw :erlang.load_nif/2 outside `use Quintessence.Nif` is forbidden"
    end

    :ok
  end

  def trace(_event, _env), do: :ok
end
