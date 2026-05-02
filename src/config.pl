:- module(config, [
    load_env_file/1,
    env_default/3,
    env_number/3,
    env_bool/3
]).

:- dynamic loaded_env/2.

load_env_file(Path) :-
    exists_file(Path),
    !,
    setup_call_cleanup(
        open(Path, read, In),
        read_env_lines(In),
        close(In)).
load_env_file(_).

read_env_lines(In) :-
    read_line_to_string(In, Line),
    (   Line == end_of_file
    ->  true
    ;   load_env_line(Line),
        read_env_lines(In)
    ).

load_env_line(Line0) :-
    normalize_space(string(Line), Line0),
    Line \= "",
    \+ sub_string(Line, 0, 1, _, "#"),
    sub_string(Line, Before, 1, After, "="),
    !,
    sub_string(Line, 0, Before, _, Key0),
    Start is Before + 1,
    sub_string(Line, Start, After, 0, Value0),
    normalize_space(string(Key), Key0),
    normalize_space(string(Value), Value0),
    retractall(loaded_env(Key, _)),
    assertz(loaded_env(Key, Value)).
load_env_line(_).

env_default(KeyAtom, Default, ValueAtom) :-
    atom_string(KeyAtom, Key),
    (   getenv(KeyAtom, Env)
    ->  atom_string(ValueAtom, Env)
    ;   loaded_env(Key, Value)
    ->  atom_string(ValueAtom, Value)
    ;   ValueAtom = Default
    ).

env_number(Key, Default, Number) :-
    env_default(Key, Default, Value),
    (   number(Value)
    ->  Number = Value
    ;   atom_number(Value, Number)
    ->  true
    ;   Number = Default
    ).

env_bool(Key, Default, Bool) :-
    env_default(Key, Default, Value),
    downcase_atom(Value, Lower),
    (   memberchk(Lower, [true, yes, '1', on])
    ->  Bool = true
    ;   memberchk(Lower, [false, no, '0', off])
    ->  Bool = false
    ;   Bool = Default
    ).
