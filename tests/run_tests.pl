:- initialization(run_tests, main).

:- use_module(library(plunit), []).
:- use_module(test_rules_ssh).
:- use_module(test_rules_nginx).
:- use_module(test_rules_tls).
:- use_module(test_rules_cloudflare).
:- use_module(test_rules_app).
:- use_module(test_rules_database).
:- use_module(test_scoring).
:- use_module(test_recommendations).
:- use_module(test_export).
:- use_module(test_target_probe).

run_tests :-
    plunit:run_tests,
    halt.
