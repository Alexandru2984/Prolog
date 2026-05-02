:- module(test_rules_ssh, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_ssh').

:- begin_tests(rules_ssh).

test(public_password_login_high, [nondet]) :-
    rules_ssh:risk([ssh_password_login_enabled(true), ssh_port_public(true)], high, ssh_bruteforce).

test(public_root_login_high, [nondet]) :-
    rules_ssh:risk([ssh_root_login_enabled(true), ssh_port_public(true)], high, ssh_root_public_login).

test(public_key_only_low, [nondet]) :-
    rules_ssh:risk([ssh_password_login_enabled(false), ssh_root_login_enabled(false), ssh_port_public(true)], low, ssh_public_reachable).

:- end_tests(rules_ssh).
