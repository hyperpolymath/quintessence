# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Reference example configuration. See README.adoc.

import Config

config :quintessence,
  layers: [:a, :b, :c],
  receipt_policy: %{
    layer_a: :level_4,
    layer_b: :level_5,
    layer_c: :level_5,
    trusted: :level_5
  },
  maxplus: %{
    threshold_us: 1_000,
    margin_us: 100,
    dirty_cpu_concurrency: 4
  },
  mailbox: %{
    default_capacity: 128,
    require_backpressure: true
  },
  mutation: %{
    enabled: true,
    threshold: 95.0,
    exclude_guards: true
  },
  echidna: %{
    endpoint: "http://127.0.0.1:8080",
    batch_kernels: [:coq, :lean4],
    batch_mode: :reprove,
    forbidden_axioms: [:propext, :classical_choice, :believe_me]
  },
  firewall: %{
    allowlist: "quintessence.macros",
    sandbox: :bubblewrap,
    double_expand: true
  }
