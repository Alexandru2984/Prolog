:- module(test_rules_database, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_database').

:- begin_tests(rules_database).

test(database_public_weak_firewall_critical, [nondet]) :-
    rules_database:risk([postgres_publicly_exposed(true), weak_firewall_posture(true)], critical, database_public_weak_firewall).

test(database_public_high, [nondet]) :-
    rules_database:risk([postgres_publicly_exposed(true)], high, postgres_public_exposure).

:- end_tests(rules_database).
