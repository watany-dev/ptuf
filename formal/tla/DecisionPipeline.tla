------------------------- MODULE DecisionPipeline -------------------------
(***************************************************************************)
(* The per-rule filter chain of `Engine::decide` (src/engine/mod.rs) and   *)
(* src/engine/filter.rs, checked against the guarantees that              *)
(* docs/design/decision-model.md and config-and-plugins.md promise.       *)
(*                                                                         *)
(* For every rule that fires:                                              *)
(*   1. apply_rule_override  (enabled / decision overlay)                  *)
(*   2. allowlist_hit_for    (suppress, unless hardDeny)                   *)
(*   3. demote_with_floor    (Deny -> Monitor in monitor mode, unless      *)
(*                            hardDeny; never below the rule's own Ask     *)
(*                            when `MonitorFloor`)                         *)
(* then `aggregate` takes the maximum kind.                                *)
(*                                                                         *)
(* The model has no dynamics: Init enumerates every combination of rule   *)
(* metadata, rule output and config, and the invariants are checked on    *)
(* each one (exhaustive enumeration, the TLC way to model-check a pure    *)
(* function).                                                              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Rules,
    MonitorFloor   \* TRUE = demote_with_floor (current), FALSE = pre-fix demote_for_mode

\* DecisionKind, ordered as in src/decision.rs: allow < monitor < ask < deny.
Allow == 0
Monitor == 1
Ask == 2
Deny == 3
Kinds == {Allow, Monitor, Ask, Deny}
NoFire == -1      \* rule.evaluate returned None
Unset == -2       \* Option::None in a RuleOverride field

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

VARIABLES
    hard,       \* rule.hard_deny()
    ovr,        \* rule.overridable()
    raw,        \* rule.evaluate(..): NoFire or a kind
    oEnabled,   \* rules.<id>.enabled : "unset" / "true" / "false"
    oDecision,  \* rules.<id>.decision: Unset or a kind
    allowed,    \* an active allowlists[] entry covers the rule
    mode        \* "enforce" / "monitor"

vars == <<hard, ovr, raw, oEnabled, oDecision, allowed, mode>>

Init ==
    /\ hard \in [Rules -> BOOLEAN]
    /\ ovr \in [Rules -> BOOLEAN]
    /\ raw \in [Rules -> {NoFire} \cup Kinds]
    /\ oEnabled \in [Rules -> {"unset", "true", "false"}]
    /\ oDecision \in [Rules -> {Unset} \cup Kinds]
    /\ allowed \in [Rules -> BOOLEAN]
    /\ mode \in {"enforce", "monitor"}

Spec == Init /\ [][UNCHANGED vars]_vars

---------------------------------------------------------------------------
(* Implementation, transcribed from src/engine/filter.rs.                 *)

IsOverridable(r) == ovr[r] /\ ~hard[r]

\* apply_rule_override: NoFire when the rule is disabled.
AfterOverride(r) ==
    IF raw[r] = NoFire THEN NoFire
    ELSE IF oEnabled[r] = "false" /\ IsOverridable(r) THEN NoFire
    ELSE IF oDecision[r] = Unset THEN raw[r]
    ELSE IF IsOverridable(r) \/ oDecision[r] >= raw[r] THEN oDecision[r]
    ELSE raw[r]

\* allowlist_hit_for: hardDeny ignores allowlists; Allow is never "hit".
AllowlistHit(r) ==
    /\ AfterOverride(r) \notin {NoFire, Allow}
    /\ ~hard[r]
    /\ allowed[r]

\* Decisions pushed into `decisions` (fired, not allowlisted).
Pushed(r) == AfterOverride(r) # NoFire /\ ~AllowlistHit(r)

\* demote_for_mode, looked up by rule id (`is_hard_deny_rule_id`).
DemoteOf(r, k) == IF mode = "monitor" /\ k = Deny /\ ~hard[r] THEN Monitor ELSE k

\* demote_with_floor: a demoted rule falls back to its own Ask, if any.
Demote(r) ==
    IF MonitorFloor /\ AfterOverride(r) = Deny /\ DemoteOf(r, Deny) = Monitor /\ raw[r] = Ask
    THEN Ask ELSE DemoteOf(r, AfterOverride(r))

Final ==
    LET ks == {Demote(r) : r \in {q \in Rules : Pushed(q)}}
    IN IF ks = {} THEN Allow ELSE Max(ks)

RawIsDeny == \E r \in Rules : Pushed(r) /\ AfterOverride(r) = Deny
ModeDemoted == RawIsDeny /\ Final # Deny
Hits == {r \in Rules : AllowlistHit(r)}
AllowlistIdSet == Final = Allow /\ Hits # {}

---------------------------------------------------------------------------
(* Documented guarantees.                                                  *)

\* decision-model.md "mode": a hardDeny rule's Deny blocks in every mode.
HardDenyAlwaysBlocks ==
    (\E r \in Rules : hard[r] /\ raw[r] = Deny) => Final = Deny

\* decision-model.md: demotion only ever lowers a Deny to Monitor.
DemotionOnlyLowersDeny ==
    mode = "enforce" => ~ModeDemoted

\* Monitor mode alone never blocks except through hardDeny.
MonitorBlocksOnlyViaHardDeny ==
    (mode = "monitor" /\ Final = Deny) =>
        \E r \in Rules : hard[r] /\ AfterOverride(r) = Deny

\* config-and-plugins.md "allowlists": allowlistId is set exactly when the
\* final decision is Allow and some entry suppressed a rule.
AllowlistIdOnlyOnAllow ==
    AllowlistIdSet => \A r \in Rules : Pushed(r) => Demote(r) = Allow

\* Tightening a rule's decision via `rules.<id>.decision` (e.g. ask ->
\* deny) must never make that rule's contribution weaker than leaving the
\* override out.
StricterOverrideNeverWeakens ==
    \A r \in Rules :
        (/\ raw[r] \in Kinds
         /\ oDecision[r] \in Kinds
         /\ oDecision[r] >= raw[r]
         /\ AfterOverride(r) = oDecision[r])
        => Demote(r) >= DemoteOf(r, raw[r])

\* The outcome never exceeds what the (overridden) rules asked for.
NoSpuriousEscalation ==
    Final <= Max({Allow} \cup {AfterOverride(r) : r \in {q \in Rules : AfterOverride(q) # NoFire}})
=============================================================================
