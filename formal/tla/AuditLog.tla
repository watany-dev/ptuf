---------------------------- MODULE AuditLog ----------------------------
(***************************************************************************)
(* Concurrent appends to the shared audit JSONL file.                      *)
(*                                                                         *)
(* Models `JsonlSink::record` (src/audit/mod.rs) and                       *)
(* `writer::append_record` (src/audit/writer.rs): every ptuf process opens *)
(* the file with O_APPEND, takes an exclusive flock(2), issues one         *)
(* `write_all` of `json ++ "\n"` (which the kernel may split into several  *)
(* partial `write(2)` calls) and unlocks. A process can die at any point   *)
(* while holding the lock: the agent's hook timeout SIGKILLs it, or        *)
(* `write_all` returns ENOSPC/EIO halfway. The kernel releases the flock   *)
(* when the descriptor closes, so the next writer proceeds.                *)
(*                                                                         *)
(* The reader is `audit::read::open_snapshot` + `scan_into`: it takes a    *)
(* shared lock, records the length, unlocks and parses that prefix line by *)
(* line.                                                                   *)
(*                                                                         *)
(* `RepairTail` toggles the fix: after taking the lock a writer checks     *)
(* whether the file ends in "\n" and, if not, terminates the torn line     *)
(* before appending its own record.                                        *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Writers,      \* ptuf processes appending one record each
    RecLen,       \* payload bytes per record (the JSON body)
    RepairTail    \* TRUE = writer terminates a torn tail before appending

NL == <<"nl", 0>>
Byte(w, i) == <<w, i>>
\* The full line a writer intends to append: payload bytes, then "\n".
Record(w) == [i \in 1..(RecLen + 1) |-> IF i = RecLen + 1 THEN NL ELSE Byte(w, i)]

VARIABLES
    file,     \* Seq of bytes on disk
    lock,     \* "free", "shared", or the writer holding the exclusive lock
    pc,       \* per-writer program counter
    written,  \* per-writer bytes of Record(w) already written
    snap      \* reader snapshot length, or -1 before the snapshot

vars == <<file, lock, pc, written, snap>>

TypeOK ==
    /\ lock \in {"free", "shared"} \cup Writers
    /\ pc \in [Writers -> {"idle", "repair", "write", "done", "dead"}]
    /\ written \in [Writers -> 0..(RecLen + 1)]
    /\ snap \in {-1} \cup 0..Len(file)

Init ==
    /\ file = <<>>
    /\ lock = "free"
    /\ pc = [w \in Writers |-> "idle"]
    /\ written = [w \in Writers |-> 0]
    /\ snap = -1

\* File::lock (flock LOCK_EX) blocks until no other holder.
Acquire(w) ==
    /\ pc[w] = "idle"
    /\ lock = "free"
    /\ lock' = w
    /\ pc' = [pc EXCEPT ![w] = IF RepairTail THEN "repair" ELSE "write"]
    /\ UNCHANGED <<file, written, snap>>

Repair(w) ==
    /\ pc[w] = "repair"
    /\ file' = IF file # <<>> /\ file[Len(file)] # NL THEN Append(file, NL) ELSE file
    /\ pc' = [pc EXCEPT ![w] = "write"]
    /\ UNCHANGED <<lock, written, snap>>

\* One `write(2)` inside `write_all`: appends a non-empty prefix of the
\* remaining bytes (O_APPEND puts it at the current end of file).
WriteSome(w) ==
    /\ pc[w] = "write"
    /\ \E k \in 1..(RecLen + 1 - written[w]) :
         /\ file' = file \o SubSeq(Record(w), written[w] + 1, written[w] + k)
         /\ written' = [written EXCEPT ![w] = @ + k]
    /\ UNCHANGED <<lock, pc, snap>>

\* `write_all` returned Ok: File::unlock and report success.
Finish(w) ==
    /\ pc[w] = "write"
    /\ written[w] = RecLen + 1
    /\ pc' = [pc EXCEPT ![w] = "done"]
    /\ lock' = "free"
    /\ UNCHANGED <<file, written, snap>>

\* SIGKILL / ENOSPC while holding the lock. Closing the fd drops the flock.
Die(w) ==
    /\ pc[w] \in {"repair", "write"}
    /\ written[w] < RecLen + 1
    /\ pc' = [pc EXCEPT ![w] = "dead"]
    /\ lock' = "free"
    /\ UNCHANGED <<file, written, snap>>

\* open_snapshot: lock_shared, read metadata().len(), unlock.
Snapshot ==
    /\ snap = -1
    /\ lock = "free"
    /\ snap' = Len(file)
    /\ UNCHANGED <<file, lock, pc, written>>

Next ==
    \/ \E w \in Writers : Acquire(w) \/ Repair(w) \/ WriteSome(w) \/ Finish(w) \/ Die(w)
    \/ Snapshot

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* What `scan_into` sees: the NL-terminated lines of a byte prefix.        *)

\* Positions of NL in s.
NLs(s) == {i \in 1..Len(s) : s[i] = NL}

\* The complete lines of s (each without its terminator).
Lines(s) ==
    { SubSeq(s, a + 1, b - 1) :
        <<a, b>> \in { <<a, b>> \in ({0} \cup NLs(s)) \X NLs(s) :
                         /\ a < b
                         /\ \A j \in NLs(s) : ~(a < j /\ j < b) } }

Payload(w) == SubSeq(Record(w), 1, RecLen)

\* SAFETY: every record whose `append_record` returned Ok is a complete,
\* parseable line of the file. A torn tail left by a dead writer must not
\* swallow the next writer's record.
AcknowledgedRecordsReadable ==
    \A w \in Writers : pc[w] = "done" => Payload(w) \in Lines(file)

\* SAFETY: a snapshot taken under the shared lock never cuts a record in
\* half unless some writer died (that is the only source of a torn tail).
SnapshotEndsOnBoundary ==
    (snap > 0 /\ \A w \in Writers : pc[w] # "dead") => file[snap] = NL

\* No two writers ever hold the exclusive lock at once.
MutualExclusion ==
    \A w1, w2 \in Writers : (pc[w1] \in {"repair", "write"} /\ pc[w2] \in {"repair", "write"}) => w1 = w2
=============================================================================
