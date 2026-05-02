:- module(test_export, []).
:- use_module(library(plunit)).
:- use_module('../src/audit_engine').
:- use_module('../src/export').

:- begin_tests(export).

test(json_export_contains_score, [nondet]) :-
    audit_engine:audit([ssh_password_login_enabled(true), ssh_port_public(true)], Result),
    export:audit_json_atom(Result, Atom),
    sub_atom(Atom, _, _, _, '"score"').

test(markdown_export_contains_recommendations, [nondet]) :-
    audit_engine:audit([ssh_password_login_enabled(true), ssh_port_public(true)], Result),
    export:audit_markdown(Result, Markdown),
    sub_string(Markdown, _, _, _, 'Recommendations').

:- end_tests(export).
