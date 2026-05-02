:- module(rules_app, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, critical, debug_public_app) :-
    has(F, debug_mode_enabled(true)),
    has(F, public_app(true)).
risk(F, high, app_public_interface) :-
    has(F, app_bound_to_public_interface(true)),
    has(F, nginx_reverse_proxy_enabled(true)).
risk(F, medium, default_admin_path) :-
    has(F, default_admin_path_enabled(true)),
    has(F, public_app(true)).
risk(F, medium, missing_rate_limiting) :-
    has(F, app_has_rate_limiting(false)),
    has(F, public_app(true)).
risk(F, critical, env_file_exposed) :-
    has(F, exposes_env_file(true)).
risk(F, high, git_directory_exposed) :-
    has(F, exposes_git_directory(true)).
risk(F, high, phpmyadmin_exposed) :-
    has(F, exposes_phpmyadmin(true)),
    has(F, public_app(true)).
