:- module(rules_tls, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, high, missing_https) :-
    has(F, public_app(true)),
    has(F, https_enabled(false)).
risk(F, medium, missing_hsts) :-
    has(F, https_enabled(true)),
    has(F, nginx_has_hsts(false)).
risk(F, medium, tls_no_auto_renewal) :-
    has(F, https_enabled(true)),
    has(F, tls_auto_renewal_enabled(false)).
risk(F, high, legacy_tls_protocols) :-
    has(F, https_enabled(true)),
    has(F, tls_modern_protocols_only(false)).
