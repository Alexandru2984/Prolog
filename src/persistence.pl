:- module(persistence, [
    save_audit_session/5,
    list_audit_sessions/1,
    load_audit_session/2
]).

:- use_module(library(http/json)).
:- use_module(library(date)).
:- use_module(library(filesex)).
:- use_module(export).

save_audit_session(Label, Facts, Result, JsonPath, MarkdownPath) :-
    make_directory_path('data/exports'),
    get_time(Now),
    format_time(atom(Stamp), '%Y%m%d-%H%M%S', Now),
    safe_label(Label, SafeLabel),
    atomic_list_concat([Stamp, '-', SafeLabel], Base),
    directory_file_path('data/exports', Base, Stem),
    file_name_extension(Stem, json, JsonPath),
    file_name_extension(Stem, md, MarkdownPath),
    export:audit_json_atom(Result.put(_{label:Label, saved_at:Stamp, facts:Facts}), JsonAtom),
    setup_call_cleanup(open(JsonPath, write, JsonOut), write(JsonOut, JsonAtom), close(JsonOut)),
    export:audit_markdown(Result.put(_{label:Label, saved_at:Stamp}), Markdown),
    setup_call_cleanup(open(MarkdownPath, write, MdOut), write(MdOut, Markdown), close(MdOut)).

list_audit_sessions(Sessions) :-
    exists_directory('data/exports'),
    !,
    directory_files('data/exports', Files),
    include(json_file, Files, JsonFiles),
    sort(JsonFiles, Sorted),
    reverse(Sorted, Desc),
    findall(_{file:F}, member(F, Desc), Sessions).
list_audit_sessions([]).

load_audit_session(File, Dict) :-
    safe_export_file(File),
    directory_file_path('data/exports', File, Path),
    setup_call_cleanup(open(Path, read, In), json_read_dict(In, Dict), close(In)).

json_file(File) :- file_name_extension(_, json, File).

safe_export_file(File) :-
    atom_string(Atom, File),
    \+ sub_atom(Atom, _, _, _, '..'),
    \+ sub_atom(Atom, _, _, _, '/'),
    file_name_extension(_, json, Atom).

safe_label(Label, Safe) :-
    string_lower(Label, Lower),
    string_chars(Lower, Chars),
    maplist(safe_char, Chars, SafeChars0),
    phrase(collapse_dashes(SafeChars0), SafeChars),
    string_chars(Safe0, SafeChars),
    (Safe0 = "" -> Safe = audit ; atom_string(Safe, Safe0)).

safe_char(C, C) :- char_type(C, alnum), !.
safe_char(_, '-').

collapse_dashes([]) --> [].
collapse_dashes(['-'|Rest]) --> ['-'], skip_dashes(Rest, Next), collapse_dashes(Next).
collapse_dashes([C|Rest]) --> [C], { C \= '-' }, collapse_dashes(Rest).

skip_dashes(['-'|Rest], Next) :- !, skip_dashes(Rest, Next).
skip_dashes(Rest, Rest).
