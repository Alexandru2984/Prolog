:- module(rules_nginx, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, critical, app_public_bind) :-
    has(F, app_bound_to_public_interface(true)),
    has(F, nginx_reverse_proxy_enabled(false)).
risk(F, high, missing_reverse_proxy) :-
    has(F, public_app(true)),
    has(F, nginx_reverse_proxy_enabled(false)).
risk(F, medium, missing_security_headers) :-
    has(F, public_app(true)),
    has(F, nginx_has_security_headers(false)).
risk(F, medium, missing_csp) :-
    has(F, public_app(true)),
    has(F, nginx_has_csp(false)).
