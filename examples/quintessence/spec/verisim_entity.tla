-------------------------------- MODULE VerisimEntity --------------------------------
(* SPDX-License-Identifier: MPL-2.0                                         *)
(* Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>         *)
(*                                                                          *)
(* Reference example. Apalache checks a bounded instance of this model.     *)
(* It is an abstraction of the protocol, not of the Elixir code.            *)
(****************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Roles, Values, MaxMailbox, MaxEpochs

VARIABLES state, mailbox, inflight, view, epoch, committed, knowledge, warrant

vars == <<state, mailbox, inflight, view, epoch, committed, knowledge, warrant>>

Init ==
    /\ state     = [r \in Roles |-> 0]
    /\ mailbox   = [r \in Roles |-> <<>>]
    /\ inflight  = {}
    /\ view      = [r \in Roles |-> <<>>]
    /\ epoch     = [r \in Roles |-> 0]
    /\ committed = [r \in Roles |-> {}]
    /\ knowledge = [r \in Roles |-> {}]
    /\ warrant   = [r \in Roles |-> {}]

Send(i, j, m) ==
    /\ i # j
    /\ Len(mailbox[j]) < MaxMailbox
    /\ mailbox'  = [mailbox EXCEPT ![j] = Append(@, m)]
    /\ inflight' = inflight \cup {<<i, j, m>>}
    /\ UNCHANGED <<state, view, epoch, committed, knowledge, warrant>>

Deliver(j) ==
    /\ Len(mailbox[j]) > 0
    /\ \E m \in {x \in inflight : x[2] = j} :
         Head(mailbox[j]) = m[3]
         /\ mailbox'  = [mailbox EXCEPT ![j] = Tail(@)]
         /\ view'     = [view EXCEPT ![j] = Append(@, m[3])]
         /\ inflight' = inflight \ {m}
         /\ UNCHANGED <<state, epoch, committed, knowledge, warrant>>

Commit(j, v) ==
    /\ v \in Values
    /\ state'     = [state EXCEPT ![j] = v]
    /\ committed' = [committed EXCEPT ![j] = @ \cup {v}]
    /\ warrant'   = [warrant EXCEPT ![j] = @ \cup {v}]
    /\ UNCHANGED <<mailbox, inflight, view, epoch, knowledge>>

(* A reply carries the warrant for a commit. The caller may only add the fact
   to its knowledge if the warrant is present. A model that omits the second
   conjunct is the mutant Apalache is expected to refute. *)
Warrant(r, f) ==
    /\ f \in warrant[r]
    /\ knowledge' = [knowledge EXCEPT ![r] = @ \cup {f}]
    /\ UNCHANGED <<state, mailbox, inflight, view, epoch, committed, warrant>>

(* The forbidden claim: a sender asserting the receiver received a cast. This
   action must never be enabled in a model that has no reply on the edge. *)
BadClaim(r, f) ==
    /\ f \notin warrant[r]
    /\ knowledge' = [knowledge EXCEPT ![r] = @ \cup {f}]
    /\ UNCHANGED <<state, mailbox, inflight, view, epoch, committed, warrant>>

Crash(j) ==
    /\ mailbox'  = [mailbox EXCEPT ![j] = <<>>]
    /\ inflight' = {x \in inflight : x[1] # j}
    /\ epoch'    = [epoch EXCEPT ![j] = @ + 1]
    /\ UNCHANGED <<state, view, committed, knowledge, warrant>>

Next ==
    \/ \E i, j \in Roles, m \in Values : Send(i, j, m)
    \/ \E j \in Roles : Deliver(j)
    \/ \E j \in Roles, v \in Values : Commit(j, v)
    \/ \E r \in Roles, f \in Values : Warrant(r, f)
    \/ \E j \in Roles : Crash(j)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

TypeOK ==
    /\ \A r \in Roles : Len(mailbox[r]) <= MaxMailbox
    /\ \A r \in Roles : epoch[r] <= MaxEpochs

MailboxBound ==
    \A r \in Roles : Len(mailbox[r]) <= MaxMailbox

NoUnwarrantedRemoteClaim ==
    \A r \in Roles, f \in knowledge[r] : f \in warrant[r]

EpochConsistent ==
    \A r \in Roles : epoch[r] <= MaxEpochs

=============================================================================
