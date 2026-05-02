:- module(test_scoring, []).
:- use_module(library(plunit)).
:- use_module('../src/scoring').
:- use_module('../src/audit_engine').

:- begin_tests(scoring).

test(score_penalties) :-
    scoring:score_from_risks([risk(critical, a), risk(high, b), risk(medium, c), risk(low, d)], Score, Posture),
    assertion(Score =:= 49),
    assertion(Posture == weak).

test(posture_strong) :- scoring:posture_for_score(95, strong).
test(posture_good) :- scoring:posture_for_score(80, good).
test(posture_needs_attention) :- scoring:posture_for_score(60, needs_attention).
test(posture_critical) :- scoring:posture_for_score(10, critical).

test(combined_risk_logic) :-
    audit_engine:audit([
        app_bound_to_public_interface(true),
        nginx_reverse_proxy_enabled(false),
        public_app(true),
        debug_mode_enabled(true)
    ], Result),
    memberchk(risk(critical, app_public_bind), Result.risks),
    memberchk(risk(critical, debug_public_app), Result.risks).

:- end_tests(scoring).
