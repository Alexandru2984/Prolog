:- module(rules_database, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, critical, database_public_weak_firewall) :-
    has(F, postgres_publicly_exposed(true)),
    has(F, weak_firewall_posture(true)).
risk(F, high, postgres_public_exposure) :-
    has(F, postgres_publicly_exposed(true)).
risk(F, medium, database_tls_not_required) :-
    has(F, public_app(true)),
    has(F, database_requires_tls(false)).
