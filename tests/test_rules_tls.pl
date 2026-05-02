:- module(test_rules_tls, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_tls').

:- begin_tests(rules_tls).

test(missing_hsts_medium, [nondet]) :-
    rules_tls:risk([https_enabled(true), nginx_has_hsts(false)], medium, missing_hsts).

test(missing_https_high, [nondet]) :-
    rules_tls:risk([public_app(true), https_enabled(false)], high, missing_https).

test(legacy_tls_high, [nondet]) :-
    rules_tls:risk([https_enabled(true), tls_modern_protocols_only(false)], high, legacy_tls_protocols).

:- end_tests(rules_tls).
