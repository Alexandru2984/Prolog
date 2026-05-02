:- module(test_rules_nginx, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_nginx').

:- begin_tests(rules_nginx).

test(app_public_bind_critical, [nondet]) :-
    rules_nginx:risk([app_bound_to_public_interface(true), nginx_reverse_proxy_enabled(false)], critical, app_public_bind).

test(missing_csp_medium, [nondet]) :-
    rules_nginx:risk([public_app(true), nginx_has_csp(false)], medium, missing_csp).

:- end_tests(rules_nginx).
