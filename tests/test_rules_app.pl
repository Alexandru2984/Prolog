:- module(test_rules_app, []).
:- use_module(library(plunit)).
:- use_module('../src/rules_app', []).
:- use_module('../src/rules_uploads', []).
:- use_module('../src/rules_backups', []).
:- use_module('../src/rules_monitoring', []).

:- begin_tests(rules_app).

test(debug_public_critical, [nondet]) :-
    rules_app:risk([debug_mode_enabled(true), public_app(true)], critical, debug_public_app).

test(unsafe_uploads_high, [nondet]) :-
    rules_uploads:risk([uploads_enabled(true), upload_extension_validation(false)], high, unsafe_upload_extensions).

test(no_backups_high, [nondet]) :-
    rules_backups:risk([production_service(true), has_backups(false)], high, no_backups_production).

test(no_monitoring_medium, [nondet]) :-
    rules_monitoring:risk([production_service(true), has_monitoring(false)], medium, no_monitoring_production).

:- end_tests(rules_app).
