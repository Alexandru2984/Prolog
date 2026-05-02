:- module(rules_ssh, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, high, ssh_bruteforce) :-
    has(F, ssh_password_login_enabled(true)),
    has(F, ssh_port_public(true)).
risk(F, high, ssh_root_public_login) :-
    has(F, ssh_root_login_enabled(true)),
    has(F, ssh_port_public(true)).
risk(F, medium, ssh_password_login_enabled) :-
    has(F, ssh_password_login_enabled(true)),
    \+ has(F, ssh_port_public(true)).
risk(F, low, ssh_public_reachable) :-
    has(F, ssh_port_public(true)),
    has(F, ssh_password_login_enabled(false)),
    has(F, ssh_root_login_enabled(false)).
