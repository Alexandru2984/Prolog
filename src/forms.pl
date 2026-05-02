:- module(forms, [
    fact_groups/1,
    profile_options/1,
    facts_from_form/2,
    facts_for_profile/2
]).

:- use_module(facts).

fact_groups([
    group('SSH', [ssh_password_login_enabled, ssh_port_public, ssh_root_login_enabled]),
    group('Nginx', [nginx_reverse_proxy_enabled, nginx_has_hsts, nginx_has_csp, nginx_has_security_headers]),
    group('TLS', [https_enabled, tls_auto_renewal_enabled, tls_modern_protocols_only]),
    group('Cloudflare', [cloudflare_proxy_enabled, origin_ip_exposed]),
    group('Application runtime', [app_bound_to_public_interface, public_app, debug_mode_enabled, default_admin_path_enabled, app_has_rate_limiting]),
    group('Database', [postgres_publicly_exposed, database_requires_tls, weak_firewall_posture, exposes_phpmyadmin, exposes_env_file, exposes_git_directory]),
    group('Uploads/files', [uploads_enabled, upload_extension_validation, upload_size_limit]),
    group('Backups', [has_backups, backups_tested]),
    group('Monitoring', [has_monitoring, has_log_rotation, production_service])
]).

profile_options(Options) :-
    findall(Id-Label, facts:sample_profile(Id, Label, _), Options).

facts_for_profile(ProfileAtom, Facts) :-
    facts:sample_profile(ProfileAtom, _, Facts),
    !.
facts_for_profile(_, Facts) :-
    facts:default_facts(Facts).

facts_from_form(FormData, Facts) :-
    option_value(FormData, profile, ProfileString, "default"),
    atom_string(ProfileAtom, ProfileString),
    facts_for_profile(ProfileAtom, BaseFacts),
    findall(Fact,
            (member(Base, BaseFacts), override_fact(Base, FormData, Fact)),
            Facts).

override_fact(Base, FormData, Fact) :-
    Base =.. [Name, _],
    atom_string(Name, Key),
    (   form_member(FormData, Key, _)
    ->  Value = true
    ;   Value = false
    ),
    Fact =.. [Name, Value].

option_value(FormData, Key, Value, Default) :-
    atom_string(Key, KeyString),
    (   form_member(FormData, KeyString, Value)
    ->  true
    ;   Value = Default
    ).

form_member(FormData, KeyString, Value) :-
    member(Pair, FormData),
    Pair = (RawKey=Value),
    key_matches(RawKey, KeyString).

key_matches(Key, KeyString) :-
    string(Key),
    !,
    Key == KeyString.
key_matches(Key, KeyString) :-
    atom(Key),
    atom_string(Key, KeyString).
