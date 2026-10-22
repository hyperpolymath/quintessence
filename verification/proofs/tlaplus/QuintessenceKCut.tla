---- MODULE QuintessenceKCut ----
EXTENDS Integers, Sequences

\* SPDX-License-Identifier: MPL-2.0
\* Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
\*
\* Reusable Layer B `K-CUT` protocol pattern for Apalache bounded model checking
\* (`apalache-mc check --length=12`) and Quintessence native SMT BMC discharge.

CONSTANTS
  \* @type: Int;
  MailboxCapacity,
  \* @type: Int;
  MaxDriftBp

VARIABLES
  \* @type: Int;
  entityVersion,
  \* @type: Int;
  entityEpoch,
  \* @type: Int;
  entityDrift,
  \* @type: Int;
  mailboxOcc,
  \* @type: Bool;
  clientKnowsCommitted,
  \* @type: Int;
  clientKnownVersion,
  \* @type: Int;
  clientEpoch

Init ==
  /\ entityVersion = 0
  /\ entityEpoch = 1
  /\ entityDrift = 0
  /\ mailboxOcc = 0
  /\ clientKnowsCommitted = FALSE
  /\ clientKnownVersion = 0
  /\ clientEpoch = 1

SendCommit ==
  /\ mailboxOcc < MailboxCapacity
  /\ mailboxOcc' = mailboxOcc + 1
  /\ UNCHANGED <<entityVersion, entityEpoch, entityDrift, clientKnowsCommitted, clientKnownVersion, clientEpoch>>

DropOrReorderAsync ==
  /\ mailboxOcc > 0
  /\ mailboxOcc' = mailboxOcc - 1
  /\ UNCHANGED <<entityVersion, entityEpoch, entityDrift, clientKnowsCommitted, clientKnownVersion, clientEpoch>>

CommitAndCausalReply(d) ==
  /\ mailboxOcc > 0
  /\ d >= 0 /\ d <= MaxDriftBp
  /\ entityEpoch = clientEpoch
  /\ mailboxOcc' = mailboxOcc - 1
  /\ entityVersion' = entityVersion + 1
  /\ entityDrift' = d
  /\ clientKnowsCommitted' = TRUE
  /\ clientKnownVersion' = entityVersion + 1
  /\ UNCHANGED <<entityEpoch, clientEpoch>>

SupervisorCrashRestart ==
  /\ entityEpoch' = entityEpoch + 1
  /\ clientEpoch' = entityEpoch + 1
  /\ clientKnowsCommitted' = FALSE
  /\ mailboxOcc' = 0
  /\ UNCHANGED <<entityVersion, entityDrift, clientKnownVersion>>

Next ==
  \/ SendCommit
  \/ DropOrReorderAsync
  \/ \E d \in 0..MaxDriftBp : CommitAndCausalReply(d)
  \/ SupervisorCrashRestart

MailboxBound ==
  mailboxOcc >= 0 /\ mailboxOcc <= MailboxCapacity

NoUnwarrantedRemoteClaim ==
  clientKnowsCommitted =>
    (entityVersion >= clientKnownVersion /\ entityEpoch = clientEpoch)

EpochConsistent ==
  entityEpoch >= 1
====
