:- module(test_target_probe, []).
:- use_module(library(plunit)).
:- use_module('../src/target_probe').

:- begin_tests(target_probe).

test(normalize_domain, [nondet]) :-
    target_probe:normalize_target('https://Example.COM/path?q=1', Target),
    assertion(Target == "example.com").

test(normalize_path_without_scheme, [nondet]) :-
    target_probe:normalize_target('example.com/admin', Target),
    assertion(Target == "example.com").

test(merge_detected_overrides_manual) :-
    target_probe:merge_detected_facts(
        [cloudflare_proxy_enabled(false), origin_ip_exposed(true), has_backups(false)],
        [cloudflare_proxy_enabled(true), origin_ip_exposed(false)],
        Merged),
    assertion(memberchk(cloudflare_proxy_enabled(true), Merged)),
    assertion(memberchk(origin_ip_exposed(false), Merged)),
    assertion(memberchk(has_backups(false), Merged)).

test(reject_loopback, [fail]) :-
    target_probe:normalize_target('127.0.0.1', _).

test(reject_metadata_ip, [fail]) :-
    target_probe:normalize_target('169.254.169.254', _).

:- end_tests(target_probe).
