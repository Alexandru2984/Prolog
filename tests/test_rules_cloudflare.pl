:- module(test_rules_cloudflare, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_cloudflare').

:- begin_tests(rules_cloudflare).

test(origin_exposed_without_proxy_high, [nondet]) :-
    rules_cloudflare:risk([cloudflare_proxy_enabled(false), origin_ip_exposed(true), public_app(true)], high, origin_exposed_without_proxy).

test(origin_exposed_medium_when_proxied, [nondet]) :-
    rules_cloudflare:risk([cloudflare_proxy_enabled(true), origin_ip_exposed(true)], medium, origin_ip_exposed).

:- end_tests(rules_cloudflare).
