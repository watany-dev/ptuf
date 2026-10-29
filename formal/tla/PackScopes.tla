---------------------------- MODULE PackScopes ----------------------------
(***************************************************************************)
(* `packs.<prefix>.enabled` across the four config scopes.                 *)
(*                                                                         *)
(* src/config/merge.rs folds the layers (system < user < repo < local) per *)
(* exact pack key: for the same key the later layer's `Some(enabled)`     *)
(* wins. src/engine/filter.rs `is_pack_disabled` then disables a rule when *)
(* ANY dot-boundary prefix of its id (or the id itself) is effectively    *)
(* `enabled: false`.                                                       *)
(*                                                                         *)
(* config-and-plugins.md says higher scopes override lower ones. The      *)
(* invariant below asks whether the highest scope that says anything about *)
(* a rule's packs actually decides whether the rule runs.                  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Layers, Keys   \* Layers = 1..N (1 = lowest priority); Keys = pack prefixes covering one rule

VARIABLES setting        \* setting[l][k] \in {"unset", "true", "false"}

Init == setting \in [Layers -> [Keys -> {"unset", "true", "false"}]]
Spec == Init /\ [][UNCHANGED setting]_setting

\* merge.rs: per key, the last layer with Some(_) wins.
Effective(k) ==
    LET ls == {l \in Layers : setting[l][k] # "unset"}
    IN IF ls = {} THEN "unset"
       ELSE setting[CHOOSE l \in ls : \A m \in ls : m <= l][k]

\* filter.rs: disabled if any covering key is effectively false.
Disabled == \E k \in Keys : Effective(k) = "false"

\* Highest layer that mentions any covering key.
Mentioning == {l \in Layers : \E k \in Keys : setting[l][k] # "unset"}
Top == CHOOSE l \in Mentioning : \A m \in Mentioning : m <= l

\* If the highest-priority scope that configures the rule's packs only
\* says `enabled: true`, the rule runs.
HigherScopeEnableWins ==
    (Mentioning # {} /\ \A k \in Keys : setting[Top][k] \in {"unset", "true"})
        => ~Disabled
=============================================================================
