:- module(rules_cloudflare, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, high, origin_exposed_without_proxy) :-
    has(F, cloudflare_proxy_enabled(false)),
    has(F, origin_ip_exposed(true)),
    has(F, public_app(true)).
risk(F, medium, cloudflare_proxy_disabled) :-
    has(F, cloudflare_proxy_enabled(false)),
    has(F, public_app(true)).
risk(F, medium, origin_ip_exposed) :-
    has(F, cloudflare_proxy_enabled(true)),
    has(F, origin_ip_exposed(true)).
