:- module(audit_engine, [audit/2]).

:- use_module(rules_ssh, []).
:- use_module(rules_nginx, []).
:- use_module(rules_tls, []).
:- use_module(rules_cloudflare, []).
:- use_module(rules_app, []).
:- use_module(rules_database, []).
:- use_module(rules_uploads, []).
:- use_module(rules_backups, []).
:- use_module(rules_monitoring, []).
:- use_module(scoring).
:- use_module(explanations).
:- use_module(recommendations).

audit(Facts, Result) :-
    findall(risk(Severity, Id), rule_risk(Facts, Severity, Id), RawRisks),
    sort(RawRisks, Risks0),
    predsort(compare_risk, Risks0, Risks),
    scoring:score_from_risks(Risks, Score, Posture),
    findall(_{id:Id, severity:Severity, explanation:Text},
            (member(risk(Severity, Id), Risks), explanations:explanation(Id, Text)),
            ExplanationChain),
    findall(_{id:RecId, risk:Id, text:Text},
            (member(risk(_, Id), Risks), recommendations:recommendation(Id, RecId, Text)),
            Recs0),
    sort(Recs0, Recommendations),
    findall(_{id:CheckId, text:CheckText},
            recommendations:checklist_item(CheckId, CheckText),
            Checklist),
    Result = _{
        facts: Facts,
        risks: Risks,
        score: Score,
        posture: Posture,
        recommendations: Recommendations,
        explanations: ExplanationChain,
        checklist: Checklist
    }.

rule_risk(F, S, I) :- rules_ssh:risk(F, S, I).
rule_risk(F, S, I) :- rules_nginx:risk(F, S, I).
rule_risk(F, S, I) :- rules_tls:risk(F, S, I).
rule_risk(F, S, I) :- rules_cloudflare:risk(F, S, I).
rule_risk(F, S, I) :- rules_app:risk(F, S, I).
rule_risk(F, S, I) :- rules_database:risk(F, S, I).
rule_risk(F, S, I) :- rules_uploads:risk(F, S, I).
rule_risk(F, S, I) :- rules_backups:risk(F, S, I).
rule_risk(F, S, I) :- rules_monitoring:risk(F, S, I).

compare_risk(Order, risk(SA, IA), risk(SB, IB)) :-
    scoring:severity_rank(SA, RA),
    scoring:severity_rank(SB, RB),
    (   RA =:= RB
    ->  compare(Order, IA, IB)
    ;   RA > RB
    ->  Order = (<)
    ;   Order = (>)
    ).
