:- module(rules_uploads, [risk/3]).

has(Facts, Term) :- memberchk(Term, Facts).

risk(F, high, unsafe_upload_extensions) :-
    has(F, uploads_enabled(true)),
    has(F, upload_extension_validation(false)).
risk(F, medium, missing_upload_size_limit) :-
    has(F, uploads_enabled(true)),
    has(F, upload_size_limit(false)).
