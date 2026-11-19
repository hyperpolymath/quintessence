;; SPDX-License-Identifier: MPL-2.0
;; SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
;;
;; manifest.scm — the Guix development shell for quintessence.
;;
;;   guix shell -m manifest.scm                  # or: just dev-shell
;;   guix time-machine -C channels.scm -- shell -m manifest.scm   # the pinned Guix
;;
;; Minted by provision-set from the languages detected here (idris2, zig).
;; Tools Guix does not package: idris2 (via pack). They come from mise, which this
;; shell provides:  guix shell -m manifest.scm -- mise install
;; Canon: hyperpolymath/standards 3-practice/provisioning/PROVISIONING-STANDARD.adoc
(specifications->manifest
 (list "git" "bash" "coreutils" "nss-certs" "just" "mise"
       "shellcheck" "chez-scheme" "gmp" "gcc-toolchain" "zig"
       ;; SMT solvers (hole H8). Pinned by the Guix commit in channels.scm, which
       ;; resolves to z3 4.13.0 and cvc5 1.3.4. Not yet run against the suite:
       ;; the measured-working versions are Z3 4.8.12 and cvc5 1.1.2.
       "z3" "cvc5"))
