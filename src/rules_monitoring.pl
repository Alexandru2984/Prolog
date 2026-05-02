:- module(rules_monitoring, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, medium, no_monitoring_production) :-
    has(F, production_service(true)),
    has(F, has_monitoring(false)).
risk(F, low, missing_log_rotation) :-
    has(F, has_log_rotation(false)).
