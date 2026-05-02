:- module(test_recommendations, []).
:- use_module(library(plunit)).
:- use_module('../src/recommendations').
:- use_module('../src/explanations').

:- begin_tests(recommendations).

test(recommendation_generation, [nondet]) :-
    recommendations:recommendation(ssh_bruteforce, disable_ssh_password_login, Text),
    sub_atom(Text, _, _, _, 'Disable SSH password login').

test(explanation_generation, [nondet]) :-
    explanations:explanation(missing_hsts, Text),
    sub_atom(Text, _, _, _, 'HSTS').

:- end_tests(recommendations).
