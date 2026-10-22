# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Reference example. Not compiled by this checkout. See README.adoc.

defmodule Verisim.Entity do
  @moduledoc """
  A VeriSimDB-style entity state GenServer.

  The protocol is the two-message reply fragment that `choreographic-types`
  proves:

      client -> entity : commit(payload)
      entity -> client : committed(version, digest)

  The auditor receives a one-way attestation. The entity never claims the
  auditor received it; there is no reply on that edge.
  """

  use GenServer
  use Quintessence.Face, layer: :b

  @max_payload 1_048_576
  @max_drift_bp 2_500

  @cap [
    read: [:entity],
    write: [:entity],
    call: [{Verisim.Nif, [hash: 2, drift: 2]}]
  ]

  @secret [payload: :confidential, digest: :public, drift: :public]
  @declassify digest: :public, reason: :commitment

  @invariant spec(
    new_state.version >= old.version and
      new_state.drift <= @max_drift_bp
  )

  @budget hash: 180, drift: 240

  @choreography [
    roles: [:client, :entity, :auditor],
    messages: [
      {:client, :entity, :commit, [:payload]},
      {:entity, :client, :committed, [:version, :digest]},
      {:entity, :auditor, :attest, [:version, :digest]}
    ],
    knowledge: [
      {:client, :entity, :committed, [:version, :digest], {:call, :commit}},
      {:auditor, :entity, :attest, [:version, :digest], {:cast, :attest}}
    ],
    forbid: [
      {:entity, :knows, {:auditor, :received, :attest}, :cast}
    ]
  ]

  # ── OTP ──────────────────────────────────────────────────────────────────

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  @post spec(new_state.version == 0 and new_state.drift == 0)
  def init(_opts) do
    {:ok, %{version: 0, digest: <<0::256>>, drift: 0, status: :active}}
  end

  @impl true
  @role :entity
  @handles {:call, :commit}
  @pre spec(byte_size(payload) <= @max_payload)
  @pre spec(state.status == :active)
  @post spec(
    case result do
      {:ok, _, _} ->
        new_state.version == old.version + 1 and
          new_state.digest == Verisim.Spec.digest_of(payload) and
          new_state.drift <= @max_drift_bp
      {:error, _} ->
        new_state == old
    end
  )
  def handle_call({:commit, payload}, _from, state) do
    case Verisim.Nif.hash(payload, state.version) do
      {:ok, digest} ->
        drift = Verisim.Nif.drift(state.digest, digest)

        if Verisim.Spec.acceptable_drift?(drift) do
          new_state = %{
            state
            | version: state.version + 1,
              digest: digest,
              drift: drift
          }

          {:reply, {:ok, new_state.version, new_state.digest}, new_state}
        else
          {:reply, {:error, :drift}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  @role :entity
  @handles {:cast, :attest}
  @post spec(new_state == old)
  def handle_cast({:attest, _version, _digest}, state) do
    # The entity sends an attestation to the auditor. It does not, and must not,
    # claim that the auditor received it: there is no reply on this edge, and
    # `AsyncKnowledge.sender-cannot-know-receipt` is the falsifier.
    {:noreply, state}
  end

  @impl true
  @post spec(new_state == old)
  def handle_info(_message, state), do: {:noreply, state}
end
