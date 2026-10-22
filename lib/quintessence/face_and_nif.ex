# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

defmodule Quintessence.Face do
  @moduledoc """
  Declarative verification Face macro for Layer A (pure sequential modules) and
  Layer B (GenServer / OTP protocol actors).

  Preserves normal BEAM runtime semantics with zero runtime overhead while
  persisting AST specifications in `__quintessence_face__/0` for `mix verify`.
  """

  defmacro __using__(opts) do
    layer = Keyword.fetch!(opts, :layer)

    quote do
      import Quintessence.Face, only: [spec: 1]

      Module.register_attribute(__MODULE__, :quintessence_layer, persist: true)
      Module.register_attribute(__MODULE__, :cap, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :secret, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :declassify, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :invariant, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :budget, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :choreography, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :pre, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :post, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :measure, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :role, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :handles, accumulate: true, persist: true)
      Module.register_attribute(__MODULE__, :trusted, accumulate: true, persist: true)

      @quintessence_layer unquote(layer)

      def __quintessence_layer__, do: @quintessence_layer
    end
  end

  defmacro spec(expr) do
    Macro.escape(expr)
  end
end

defmodule Quintessence.Nif do
  @moduledoc """
  Verified native boundary macro for Layer C (`use Quintessence.Nif`).

  Generates `@on_load :__quintessence_load_nif__`, verifying the cryptographic
  SHA-256 of the compiled `.so` shared library against the JCS receipt BEFORE
  invoking `:erlang.load_nif/2`.
  """

  defmacro __using__(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    library = Keyword.fetch!(opts, :library)
    receipt = Keyword.fetch!(opts, :receipt)

    quote do
      @type __quintessence_nif__ :: :verified_boundary
      Module.register_attribute(__MODULE__, :nif, accumulate: true, persist: true)

      @on_load :__quintessence_load_nif__

      def __quintessence_load_nif__ do
        priv_dir = :code.priv_dir(unquote(otp_app))
        so_base = Path.join([to_string(priv_dir), "native", unquote(library)])
        so_file = "lib#{unquote(library)}.so"
        so_path = Path.join([to_string(priv_dir), "native", so_file])
        receipt_path = Path.join([File.cwd!(), unquote(receipt)])

        with {:ok, so_bytes} <- File.read(so_path),
             {:ok, receipt_bytes} <- File.read(receipt_path),
             true <-
               String.contains?(
                 receipt_bytes,
                 Base.encode16(:crypto.hash(:sha256, so_bytes), case: :lower)
               ) do
          :erlang.load_nif(String.to_charlist(so_base), 0)
        else
          _ -> {:error, {:quintessence_receipt_rejected, :q_303}}
        end
      end
    end
  end
end
