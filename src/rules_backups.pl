:- module(rules_backups, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, high, no_backups_production) :-
    has(F, production_service(true)),
    has(F, has_backups(false)).
risk(F, medium, backups_not_tested) :-
    has(F, has_backups(true)),
    has(F, backups_tested(false)).
